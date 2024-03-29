// Code generated by mockery v2.42.0. DO NOT EDIT.

package mocks

import (
	ber "github.com/go-asn1-ber/asn1-ber"

	mock "github.com/stretchr/testify/mock"
)

// Control is an autogenerated mock type for the Control type
type Control struct {
	mock.Mock
}

type Control_Expecter struct {
	mock *mock.Mock
}

func (_m *Control) EXPECT() *Control_Expecter {
	return &Control_Expecter{mock: &_m.Mock}
}

// Encode provides a mock function with given fields:
func (_m *Control) Encode() *ber.Packet {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Encode")
	}

	var r0 *ber.Packet
	if rf, ok := ret.Get(0).(func() *ber.Packet); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ber.Packet)
		}
	}

	return r0
}

// Control_Encode_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Encode'
type Control_Encode_Call struct {
	*mock.Call
}

// Encode is a helper method to define mock.On call
func (_e *Control_Expecter) Encode() *Control_Encode_Call {
	return &Control_Encode_Call{Call: _e.mock.On("Encode")}
}

func (_c *Control_Encode_Call) Run(run func()) *Control_Encode_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Control_Encode_Call) Return(_a0 *ber.Packet) *Control_Encode_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Control_Encode_Call) RunAndReturn(run func() *ber.Packet) *Control_Encode_Call {
	_c.Call.Return(run)
	return _c
}

// GetControlType provides a mock function with given fields:
func (_m *Control) GetControlType() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetControlType")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Control_GetControlType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetControlType'
type Control_GetControlType_Call struct {
	*mock.Call
}

// GetControlType is a helper method to define mock.On call
func (_e *Control_Expecter) GetControlType() *Control_GetControlType_Call {
	return &Control_GetControlType_Call{Call: _e.mock.On("GetControlType")}
}

func (_c *Control_GetControlType_Call) Run(run func()) *Control_GetControlType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Control_GetControlType_Call) Return(_a0 string) *Control_GetControlType_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Control_GetControlType_Call) RunAndReturn(run func() string) *Control_GetControlType_Call {
	_c.Call.Return(run)
	return _c
}

// String provides a mock function with given fields:
func (_m *Control) String() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for String")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Control_String_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'String'
type Control_String_Call struct {
	*mock.Call
}

// String is a helper method to define mock.On call
func (_e *Control_Expecter) String() *Control_String_Call {
	return &Control_String_Call{Call: _e.mock.On("String")}
}

func (_c *Control_String_Call) Run(run func()) *Control_String_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Control_String_Call) Return(_a0 string) *Control_String_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Control_String_Call) RunAndReturn(run func() string) *Control_String_Call {
	_c.Call.Return(run)
	return _c
}

// NewControl creates a new instance of Control. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewControl(t interface {
	mock.TestingT
	Cleanup(func())
}) *Control {
	mock := &Control{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
