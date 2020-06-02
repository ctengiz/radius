// Code generated by radius-dict-gen. DO NOT EDIT.

package rfc3162

import (
	"net"

	"github.com/ctengiz/radius"
)

const (
	NASIPv6Address_Type    radius.Type = 95
	FramedInterfaceID_Type radius.Type = 96
	FramedIPv6Prefix_Type  radius.Type = 97
	LoginIPv6Host_Type     radius.Type = 98
	FramedIPv6Route_Type   radius.Type = 99
	FramedIPv6Pool_Type    radius.Type = 100
)

func NASIPv6Address_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Add(NASIPv6Address_Type, a)
	return
}

func NASIPv6Address_Get(p *radius.Packet) (value net.IP) {
	value, _ = NASIPv6Address_Lookup(p)
	return
}

func NASIPv6Address_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, avp := range p.Attributes {
		if avp.Type != NASIPv6Address_Type {
			continue
		}
		attr := avp.Attribute
		i, err = radius.IPv6Addr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASIPv6Address_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(NASIPv6Address_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Addr(a)
	return
}

func NASIPv6Address_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Set(NASIPv6Address_Type, a)
	return
}

func NASIPv6Address_Del(p *radius.Packet) {
	p.Attributes.Del(NASIPv6Address_Type)
}

func FramedInterfaceID_Add(p *radius.Packet, value net.HardwareAddr) (err error) {
	var a radius.Attribute
	a, err = radius.NewIFID(value)
	if err != nil {
		return
	}
	p.Add(FramedInterfaceID_Type, a)
	return
}

func FramedInterfaceID_Get(p *radius.Packet) (value net.HardwareAddr) {
	value, _ = FramedInterfaceID_Lookup(p)
	return
}

func FramedInterfaceID_Gets(p *radius.Packet) (values []net.HardwareAddr, err error) {
	var i net.HardwareAddr
	for _, avp := range p.Attributes {
		if avp.Type != FramedInterfaceID_Type {
			continue
		}
		attr := avp.Attribute
		i, err = radius.IFID(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedInterfaceID_Lookup(p *radius.Packet) (value net.HardwareAddr, err error) {
	a, ok := p.Lookup(FramedInterfaceID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IFID(a)
	return
}

func FramedInterfaceID_Set(p *radius.Packet, value net.HardwareAddr) (err error) {
	var a radius.Attribute
	a, err = radius.NewIFID(value)
	if err != nil {
		return
	}
	p.Set(FramedInterfaceID_Type, a)
	return
}

func FramedInterfaceID_Del(p *radius.Packet) {
	p.Attributes.Del(FramedInterfaceID_Type)
}

func FramedIPv6Prefix_Add(p *radius.Packet, value *net.IPNet) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Prefix(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Prefix_Type, a)
	return
}

func FramedIPv6Prefix_Get(p *radius.Packet) (value *net.IPNet) {
	value, _ = FramedIPv6Prefix_Lookup(p)
	return
}

func FramedIPv6Prefix_Gets(p *radius.Packet) (values []*net.IPNet, err error) {
	var i *net.IPNet
	for _, avp := range p.Attributes {
		if avp.Type != FramedIPv6Prefix_Type {
			continue
		}
		attr := avp.Attribute
		i, err = radius.IPv6Prefix(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Prefix_Lookup(p *radius.Packet) (value *net.IPNet, err error) {
	a, ok := p.Lookup(FramedIPv6Prefix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Prefix(a)
	return
}

func FramedIPv6Prefix_Set(p *radius.Packet, value *net.IPNet) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Prefix(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Prefix_Type, a)
	return
}

func FramedIPv6Prefix_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPv6Prefix_Type)
}

func LoginIPv6Host_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Add(LoginIPv6Host_Type, a)
	return
}

func LoginIPv6Host_Get(p *radius.Packet) (value net.IP) {
	value, _ = LoginIPv6Host_Lookup(p)
	return
}

func LoginIPv6Host_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, avp := range p.Attributes {
		if avp.Type != LoginIPv6Host_Type {
			continue
		}
		attr := avp.Attribute
		i, err = radius.IPv6Addr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginIPv6Host_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(LoginIPv6Host_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Addr(a)
	return
}

func LoginIPv6Host_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Set(LoginIPv6Host_Type, a)
	return
}

func LoginIPv6Host_Del(p *radius.Packet) {
	p.Attributes.Del(LoginIPv6Host_Type)
}

func FramedIPv6Route_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Route_Type, a)
	return
}

func FramedIPv6Route_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Route_Type, a)
	return
}

func FramedIPv6Route_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedIPv6Route_Lookup(p)
	return
}

func FramedIPv6Route_GetString(p *radius.Packet) (value string) {
	value, _ = FramedIPv6Route_LookupString(p)
	return
}

func FramedIPv6Route_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, avp := range p.Attributes {
		if avp.Type != FramedIPv6Route_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Route_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, avp := range p.Attributes {
		if avp.Type != FramedIPv6Route_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Route_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedIPv6Route_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedIPv6Route_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedIPv6Route_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedIPv6Route_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Route_Type, a)
	return
}

func FramedIPv6Route_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Route_Type, a)
	return
}

func FramedIPv6Route_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPv6Route_Type)
}

func FramedIPv6Pool_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedIPv6Pool_Lookup(p)
	return
}

func FramedIPv6Pool_GetString(p *radius.Packet) (value string) {
	value, _ = FramedIPv6Pool_LookupString(p)
	return
}

func FramedIPv6Pool_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, avp := range p.Attributes {
		if avp.Type != FramedIPv6Pool_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Pool_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, avp := range p.Attributes {
		if avp.Type != FramedIPv6Pool_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Pool_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedIPv6Pool_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedIPv6Pool_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedIPv6Pool_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedIPv6Pool_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPv6Pool_Type)
}
