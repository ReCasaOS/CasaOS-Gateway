package route

import (
	"crypto/ecdsa"
	"errors"
	"net/http"
	"strconv"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Gateway/pkg/guard"
	"github.com/ReCasaOS/CasaOS-Gateway/service"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"
)

type ManagementRoute struct {
	management *service.Management
}

func NewManagementRoute(management *service.Management) *ManagementRoute {
	return &ManagementRoute{
		management: management,
	}
}

func (m *ManagementRoute) GetRoute() http.Handler {
	e := echo.New()

	e.Use((echo_middleware.CORSWithConfig(echo_middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{echo.POST, echo.GET, echo.OPTIONS, echo.PUT, echo.DELETE},
		AllowHeaders:     []string{echo.HeaderAuthorization, echo.HeaderContentLength, echo.HeaderXCSRFToken, echo.HeaderContentType, echo.HeaderAccessControlAllowOrigin, echo.HeaderAccessControlAllowHeaders, echo.HeaderAccessControlAllowMethods, echo.HeaderConnection, echo.HeaderOrigin, echo.HeaderXRequestedWith},
		ExposeHeaders:    []string{echo.HeaderContentLength, echo.HeaderAccessControlAllowOrigin, echo.HeaderAccessControlAllowHeaders},
		MaxAge:           172800,
		AllowCredentials: true,
	})))

	e.Use(echo_middleware.Gzip())

	e.GET("/ping", func(ctx echo.Context) error {
		return ctx.JSON(http.StatusOK, echo.Map{
			"message": "pong from management service",
		})
	})

	m.buildV1Group(e)

	return e
}

func (m *ManagementRoute) buildV1Group(e *echo.Echo) {
	v1Group := e.Group("/v1")

	// Routes register here and the dashboard changes the port here (through
	// the gateway, which proxies /v1/gateway/port to this server). The first
	// is a service with this boot's internal secret; the second is a person
	// with a token. Anything else on the box used to be able to re-route the
	// dashboard's API, or move its port, with a plain request to loopback.
	v1Group.Use(echojwt.WithConfig(echojwt.Config{
		Skipper: func(c echo.Context) bool {
			return external.IsInternalRequest(c.RealIP(), c.Request().Header.Get(echo.HeaderAuthorization), m.management.State.GetRuntimePath())
		},
		ParseTokenFunc: func(c echo.Context, token string) (interface{}, error) {
			valid, claims, err := jwt.Validate(token, func() (*ecdsa.PublicKey, error) { return external.GetPublicKey(m.management.State.GetRuntimePath()) })
			if err != nil || !valid {
				return nil, echo.ErrUnauthorized
			}

			c.Request().Header.Set("user_id", strconv.Itoa(claims.ID))

			return claims, nil
		},
		TokenLookupFuncs: []echo_middleware.ValuesExtractor{
			func(c echo.Context) ([]string, error) {
				return []string{jwt.TokenFromAuthorization(c.Request().Header.Get(echo.HeaderAuthorization))}, nil
			},
		},
	}))
	{
		m.buildV1RouteGroup(v1Group)
	}
}

func (m *ManagementRoute) buildV1RouteGroup(v1Group *echo.Group) {
	v1GatewayGroup := v1Group.Group("/gateway")

	v1GatewayGroup.Use()
	{
		v1GatewayGroup.GET("/routes", func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, m.management.GetRoutes())
		})

		v1GatewayGroup.POST("/routes",
			func(ctx echo.Context) error {
				var route *model.Route
				err := ctx.Bind(&route)
				if err != nil {
					return ctx.JSON(http.StatusBadRequest, model.Result{
						Success: common_err.CLIENT_ERROR,
						Message: err.Error(),
					})
				}

				if err := m.management.CreateRoute(route); err != nil {
					return ctx.JSON(http.StatusInternalServerError, model.Result{
						Success: common_err.SERVICE_ERROR,
						Message: err.Error(),
					})
				}

				return ctx.NoContent(http.StatusCreated)
			})

		// Hosts of shared apps: one name on the box's domain to one local target.
		v1GatewayGroup.GET("/hosts", func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, m.management.GetHosts())
		})

		v1GatewayGroup.PUT("/hosts", func(ctx echo.Context) error {
			var host service.HostRoute

			if err := ctx.Bind(&host); err != nil {
				return ctx.JSON(http.StatusBadRequest, model.Result{
					Success: common_err.CLIENT_ERROR,
					Message: "a host and a target are required",
				})
			}

			if err := m.management.SetHost(host); err != nil {
				if errors.Is(err, service.ErrBadHost) || errors.Is(err, service.ErrBadTarget) {
					return ctx.JSON(http.StatusBadRequest, model.Result{
						Success: common_err.CLIENT_ERROR,
						Message: err.Error(),
					})
				}

				return ctx.JSON(http.StatusInternalServerError, model.Result{
					Success: common_err.SERVICE_ERROR,
					Message: err.Error(),
				})
			}

			return ctx.NoContent(http.StatusCreated)
		})

		v1GatewayGroup.DELETE("/hosts/:host", func(ctx echo.Context) error {
			if err := m.management.DeleteHost(ctx.Param("host")); err != nil {
				return ctx.JSON(http.StatusInternalServerError, model.Result{
					Success: common_err.SERVICE_ERROR,
					Message: err.Error(),
				})
			}

			return ctx.NoContent(http.StatusNoContent)
		})

		// Protection of the shared apps: the core pushes the whole config, atomically.
		v1GatewayGroup.GET("/guard", func(ctx echo.Context) error {
			if m.management.Guard == nil {
				return ctx.NoContent(http.StatusNotFound)
			}

			return ctx.JSON(http.StatusOK, m.management.Guard.Status())
		})

		v1GatewayGroup.PUT("/guard", func(ctx echo.Context) error {
			if m.management.Guard == nil {
				return ctx.NoContent(http.StatusNotFound)
			}

			var c guard.Config

			if err := ctx.Bind(&c); err != nil {
				return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: "a guard config is required"})
			}

			if err := m.management.Guard.SetConfig(c); err != nil {
				if errors.Is(err, guard.ErrInvalid) {
					return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: err.Error()})
				}

				return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
			}

			return ctx.NoContent(http.StatusNoContent)
		})

		v1GatewayGroup.GET("/port", func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.SUCCESS),
				Data:    m.management.GetGatewayPort(),
			})
		})

		// The port of the HTTPS listener the gateway makes for itself: a number, or
		// "0" for none, which frees 443 for a proxy of one's own.
		v1GatewayGroup.GET("/httpsport", func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.SUCCESS),
				Data:    m.management.GetHTTPSPort(),
			})
		})

		v1GatewayGroup.PUT("/httpsport", func(ctx echo.Context) error {
			var request *model.ChangePortRequest

			if err := ctx.Bind(&request); err != nil || request == nil {
				return ctx.JSON(http.StatusBadRequest, model.Result{
					Success: common_err.CLIENT_ERROR,
					Message: "a port is required",
				})
			}

			if err := m.management.SetHTTPSPort(request.Port); err != nil {
				return ctx.JSON(http.StatusBadRequest, model.Result{
					Success: common_err.CLIENT_ERROR,
					Message: err.Error(),
				})
			}

			return ctx.JSON(http.StatusOK, model.Result{
				Success: common_err.SUCCESS,
				Message: common_err.GetMsg(common_err.SUCCESS),
			})
		})

		v1GatewayGroup.PUT("/port",
			func(ctx echo.Context) error {
				var request *model.ChangePortRequest

				if err := ctx.Bind(&request); err != nil {
					return ctx.JSON(http.StatusBadRequest, model.Result{
						Success: common_err.CLIENT_ERROR,
						Message: err.Error(),
					})
				}

				if err := m.management.SetGatewayPort(request.Port); err != nil {
					return ctx.JSON(http.StatusInternalServerError, model.Result{
						Success: common_err.SERVICE_ERROR,
						Message: err.Error(),
					})
				}

				return ctx.JSON(http.StatusOK, model.Result{
					Success: common_err.SUCCESS,
					Message: common_err.GetMsg(common_err.SUCCESS),
				})
			})
	}
}
