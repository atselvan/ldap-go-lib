// Code generated by mockery v2.42.0. DO NOT EDIT.

package mocks

import (
	ldap "github.com/go-ldap/ldap/v3"
	mock "github.com/stretchr/testify/mock"
)

// Response is an autogenerated mock type for the Response type
type Response struct {
	mock.Mock
}

type Response_Expecter struct {
	mock *mock.Mock
}

func (_m *Response) EXPECT() *Response_Expecter {
	return &Response_Expecter{mock: &_m.Mock}
}

// Controls provides a mock function with given fields:
func (_m *Response) Controls() []ldap.Control {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Controls")
	}

	var r0 []ldap.Control
	if rf, ok := ret.Get(0).(func() []ldap.Control); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]ldap.Control)
		}
	}

	return r0
}

// Response_Controls_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Controls'
type Response_Controls_Call struct {
	*mock.Call
}

// Controls is a helper method to define mock.On call
func (_e *Response_Expecter) Controls() *Response_Controls_Call {
	return &Response_Controls_Call{Call: _e.mock.On("Controls")}
}

func (_c *Response_Controls_Call) Run(run func()) *Response_Controls_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Response_Controls_Call) Return(_a0 []ldap.Control) *Response_Controls_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Response_Controls_Call) RunAndReturn(run func() []ldap.Control) *Response_Controls_Call {
	_c.Call.Return(run)
	return _c
}

// Entry provides a mock function with given fields:
func (_m *Response) Entry() *ldap.Entry {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Entry")
	}

	var r0 *ldap.Entry
	if rf, ok := ret.Get(0).(func() *ldap.Entry); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ldap.Entry)
		}
	}

	return r0
}

// Response_Entry_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Entry'
type Response_Entry_Call struct {
	*mock.Call
}

// Entry is a helper method to define mock.On call
func (_e *Response_Expecter) Entry() *Response_Entry_Call {
	return &Response_Entry_Call{Call: _e.mock.On("Entry")}
}

func (_c *Response_Entry_Call) Run(run func()) *Response_Entry_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Response_Entry_Call) Return(_a0 *ldap.Entry) *Response_Entry_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Response_Entry_Call) RunAndReturn(run func() *ldap.Entry) *Response_Entry_Call {
	_c.Call.Return(run)
	return _c
}

// Err provides a mock function with given fields:
func (_m *Response) Err() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Err")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Response_Err_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Err'
type Response_Err_Call struct {
	*mock.Call
}

// Err is a helper method to define mock.On call
func (_e *Response_Expecter) Err() *Response_Err_Call {
	return &Response_Err_Call{Call: _e.mock.On("Err")}
}

func (_c *Response_Err_Call) Run(run func()) *Response_Err_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Response_Err_Call) Return(_a0 error) *Response_Err_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Response_Err_Call) RunAndReturn(run func() error) *Response_Err_Call {
	_c.Call.Return(run)
	return _c
}

// Next provides a mock function with given fields:
func (_m *Response) Next() bool {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Next")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Response_Next_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Next'
type Response_Next_Call struct {
	*mock.Call
}

// Next is a helper method to define mock.On call
func (_e *Response_Expecter) Next() *Response_Next_Call {
	return &Response_Next_Call{Call: _e.mock.On("Next")}
}

func (_c *Response_Next_Call) Run(run func()) *Response_Next_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Response_Next_Call) Return(_a0 bool) *Response_Next_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Response_Next_Call) RunAndReturn(run func() bool) *Response_Next_Call {
	_c.Call.Return(run)
	return _c
}

// Referral provides a mock function with given fields:
func (_m *Response) Referral() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Referral")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Response_Referral_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Referral'
type Response_Referral_Call struct {
	*mock.Call
}

// Referral is a helper method to define mock.On call
func (_e *Response_Expecter) Referral() *Response_Referral_Call {
	return &Response_Referral_Call{Call: _e.mock.On("Referral")}
}

func (_c *Response_Referral_Call) Run(run func()) *Response_Referral_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Response_Referral_Call) Return(_a0 string) *Response_Referral_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Response_Referral_Call) RunAndReturn(run func() string) *Response_Referral_Call {
	_c.Call.Return(run)
	return _c
}

// NewResponse creates a new instance of Response. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewResponse(t interface {
	mock.TestingT
	Cleanup(func())
}) *Response {
	mock := &Response{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}