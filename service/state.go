package service

type State struct {
	gatewayPort         string
	onGatewayPortChange []func(string) error

	httpsPort         string
	onHTTPSPortChange []func(string) error

	runtimePath string
	wwwPath     string
}

func NewState() *State {
	return &State{
		gatewayPort:         "",
		onGatewayPortChange: make([]func(string) error, 0),

		runtimePath: "",
		wwwPath:     "",
	}
}

func (c *State) SetGatewayPort(port string) (err error) {
	defer func() {
		if err == nil {
			c.gatewayPort = port
		}
	}()
	return c.notifyOnGatewayPortChange(port)
}

func (c *State) GetGatewayPort() string {
	return c.gatewayPort
}

func (c *State) SetHTTPSPort(port string) (err error) {
	for i := len(c.onHTTPSPortChange) - 1; i >= 0; i-- {
		if err := c.onHTTPSPortChange[i](port); err != nil {
			return err
		}
	}

	c.httpsPort = port

	return nil
}

func (c *State) GetHTTPSPort() string {
	return c.httpsPort
}

// Same as OnGatewayPortChange, for the HTTPS port: the first func registered is the last to run.
func (c *State) OnHTTPSPortChange(f func(string) error) {
	c.onHTTPSPortChange = append(c.onHTTPSPortChange, f)
}

// Add func `f` to the stack. The stack of funcs will be called, in reverse order, when there is request to change the port.
func (c *State) OnGatewayPortChange(f func(string) error) {
	c.onGatewayPortChange = append(c.onGatewayPortChange, f)
}

func (c *State) notifyOnGatewayPortChange(port string) error {
	for i := len(c.onGatewayPortChange) - 1; i >= 0; i-- {
		if err := c.onGatewayPortChange[i](port); err != nil {
			return err
		}
	}

	return nil
}

func (c *State) SetRuntimePath(path string) error {
	c.runtimePath = path
	return nil
}

func (c *State) GetRuntimePath() string {
	return c.runtimePath
}

func (c *State) SetWWWPath(path string) error {
	c.wwwPath = path
	return nil
}

func (c *State) GetWWWPath() string {
	return c.wwwPath
}
