package netlink

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Constants used in TcU32Sel.Flags.
const (
	TC_U32_TERMINAL  = nl.TC_U32_TERMINAL
	TC_U32_OFFSET    = nl.TC_U32_OFFSET
	TC_U32_VAROFFSET = nl.TC_U32_VAROFFSET
	TC_U32_EAT       = nl.TC_U32_EAT
)

// Sel of the U32 filters that contains multiple TcU32Key. This is the type
// alias and the frontend representation of nl.TcU32Sel. It is serialized into
// canonical nl.TcU32Sel with the appropriate endianness.
type TcU32Sel = nl.TcU32Sel

// TcU32Key contained of Sel in the U32 filters. This is the type alias and the
// frontend representation of nl.TcU32Key. It is serialized into chanonical
// nl.TcU32Sel with the appropriate endianness.
type TcU32Key = nl.TcU32Key

// U32 filters on many packet related properties
type U32 struct {
	FilterAttrs
	ClassId    uint32
	Divisor    uint32 // Divisor MUST be power of 2.
	Hash       uint32
	RedirIndex int
	Sel        *TcU32Sel
	Actions    []Action
}

func (filter *U32) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

func (filter *U32) Type() string {
	return "u32"
}

// Fw filter filters on firewall marks
// NOTE: this is in filter_linux because it refers to nl.TcPolice which
//       is defined in nl/tc_linux.go
type Fw struct {
	FilterAttrs
	ClassId uint32
	// TODO remove nl type from interface
	Police nl.TcPolice
	InDev  string
	// TODO Action
	Mask   uint32
	AvRate uint32
	Rtab   [256]uint32
	Ptab   [256]uint32
}

func NewFw(attrs FilterAttrs, fattrs FilterFwAttrs) (*Fw, error) {
	var rtab [256]uint32
	var ptab [256]uint32
	rcellLog := -1
	pcellLog := -1
	avrate := fattrs.AvRate / 8
	police := nl.TcPolice{}
	police.Rate.Rate = fattrs.Rate / 8
	police.PeakRate.Rate = fattrs.PeakRate / 8
	buffer := fattrs.Buffer
	linklayer := nl.LINKLAYER_ETHERNET

	if fattrs.LinkLayer != nl.LINKLAYER_UNSPEC {
		linklayer = fattrs.LinkLayer
	}

	police.Action = int32(fattrs.Action)
	if police.Rate.Rate != 0 {
		police.Rate.Mpu = fattrs.Mpu
		police.Rate.Overhead = fattrs.Overhead
		if CalcRtable(&police.Rate, rtab[:], rcellLog, fattrs.Mtu, linklayer) < 0 {
			return nil, errors.New("TBF: failed to calculate rate table")
		}
		police.Burst = Xmittime(uint64(police.Rate.Rate), uint32(buffer))
	}
	police.Mtu = fattrs.Mtu
	if police.PeakRate.Rate != 0 {
		police.PeakRate.Mpu = fattrs.Mpu
		police.PeakRate.Overhead = fattrs.Overhead
		if CalcRtable(&police.PeakRate, ptab[:], pcellLog, fattrs.Mtu, linklayer) < 0 {
			return nil, errors.New("POLICE: failed to calculate peak rate table")
		}
	}

	return &Fw{
		FilterAttrs: attrs,
		ClassId:     fattrs.ClassId,
		InDev:       fattrs.InDev,
		Mask:        fattrs.Mask,
		Police:      police,
		AvRate:      avrate,
		Rtab:        rtab,
		Ptab:        ptab,
	}, nil
}

func (filter *Fw) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

func (filter *Fw) Type() string {
	return "fw"
}

// Flower filter represents "flower" classifier.
type Flower struct {
	FilterAttrs
	ClassId uint32
	Flags   uint32
	Keys    map[int]FlowerKey
	Actions []Action
}

func NewFlowerFilter(attrs FilterAttrs, classId, flags uint32) *Flower {
	return &Flower{
		FilterAttrs: attrs,
		ClassId:     classId,
		Flags:       flags,
		Keys:        make(map[int]FlowerKey),
	}
}

func (filter *Flower) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

func (filter *Flower) Type() string {
	return "flower"
}

// String() returns human readable representation of the flower filter,
// including filter attributes, flags, keys and actions
func (filter *Flower) String() string {
	str := "Flower{Attrs" + filter.FilterAttrs.String()
	str += fmt.Sprintf(", ClassId: %d, ", filter.ClassId)
	var first bool
	if filter.Flags == 0 {
		str += "Flags: none"
	} else {
		str += "Flags: "
		first = true
		for flag := uint32(1); flag <= nl.TCA_CLS_FLAGS_LAST; flag = flag << 1 {
			if filter.Flags&flag != 0 {
				if first {
					first = false
				} else {
					str += "|"
				}
				switch flag {
				case nl.TCA_CLS_FLAGS_SKIP_HW:
					str += "skip_hw"
				case nl.TCA_CLS_FLAGS_SKIP_SW:
					str += "skip_sw"
				case nl.TCA_CLS_FLAGS_IN_HW:
					str += "in_hw"
				case nl.TCA_CLS_FLAGS_NOT_IN_HW:
					str += "not_in_hw"
				case nl.TCA_CLS_FLAGS_VERBOSE:
					str += "verbose"
				}
			}
		}
	}
	if len(filter.Keys) != 0 {
		str += ", Keys{"
		first = true
		for i := nl.TCA_FLOWER_KEY_ETH_DST; i < nl.TCA_FLOWER_MAX; i++ {
			if key, exist := filter.Keys[i]; exist {
				if first {
					first = false
				} else {
					str += ", "
				}
				str += fmt.Sprintf("%s", key)
			}
		}
		str += "}"
	}
	if len(filter.Actions) != 0 {
		str += ", Actions{"
		first = true
		for _, act := range filter.Actions {
			if first {
				first = false
			} else {
				str += ", "
			}
			str += fmt.Sprintf("%v", act)
		}
		str += "}"
	}
	str += "}"
	return str
}

// with methods, hidden from user, for generic key's types
func (filter *Flower) withKeyEth(id int, addr net.HardwareAddr) *Flower {
	filter.Keys[id] = &FlowerKeyEthAddr{id: id, addr: addr}
	return filter
}

func (filter *Flower) withKeyU8(id int, val uint8) *Flower {
	filter.Keys[id] = &FlowerKeyU8{id: id, val: val}
	return filter
}

func (filter *Flower) withKeyU16(id int, val uint16) *Flower {
	filter.Keys[id] = &FlowerKeyU16{id: id, val: val}
	return filter
}

// WithKey methods allow chained flower keys creation. For ex.:
//
// filter = filter.WithKeyEthSrc(srcAddr).WithKeyIpProto(unix.IPPROTO_ICMP)
//
// If key can be masked, there is coresponding WithMasked method:
//
// filter = filter.WithMaskedKeyEthSrc(srcAddr, srcAddrMask)
//
// NOTE: masked key still created with mask even if WithKey method used.
// It's for ensurance that kernel didn't zeroed key because of bug, for ex..
// Usualy kernel do set mask if it's not specified for such keys.

func (filter *Flower) WithKeyEthDst(addr net.HardwareAddr) *Flower {
	return filter.withKeyEth(nl.TCA_FLOWER_KEY_ETH_DST, addr).
		withKeyEth(nl.TCA_FLOWER_KEY_ETH_DST_MASK, ethAddrMask())
}

func (filter *Flower) WithMaskedEthDst(addr, mask net.HardwareAddr) *Flower {
	return filter.withKeyEth(nl.TCA_FLOWER_KEY_ETH_DST, addr).
		withKeyEth(nl.TCA_FLOWER_KEY_ETH_DST_MASK, mask)
}

func (filter *Flower) WithKeyEthSrc(addr net.HardwareAddr) *Flower {
	return filter.withKeyEth(nl.TCA_FLOWER_KEY_ETH_SRC, addr).
		withKeyEth(nl.TCA_FLOWER_KEY_ETH_SRC_MASK, ethAddrMask())
}

func (filter *Flower) WithMaskedEthSrc(addr, mask net.HardwareAddr) *Flower {
	return filter.withKeyEth(nl.TCA_FLOWER_KEY_ETH_SRC, addr).
		withKeyEth(nl.TCA_FLOWER_KEY_ETH_SRC_MASK, mask)
}

func (filter *Flower) WithKeyEthType(val uint16) *Flower {
	return filter.withKeyU16(nl.TCA_FLOWER_KEY_ETH_TYPE, val)
}

func (filter *Flower) WithKeyIpProto(val uint8) *Flower {
	return filter.withKeyU8(nl.TCA_FLOWER_KEY_IP_PROTO, val)
}

func (filter *Flower) WithKeyVlanID(val uint16) *Flower {
	filter.Keys[nl.TCA_FLOWER_KEY_VLAN_ID] = &FlowerKeyVlanID{id: nl.TCA_FLOWER_KEY_VLAN_ID, val: val}
	return filter
}

func (filter *Flower) WithKeyVlanPrio(val uint8) *Flower {
	return filter.withKeyU8(nl.TCA_FLOWER_KEY_VLAN_PRIO, val)
}

func (filter *Flower) WithKeyVlanEthType(val uint16) *Flower {
	return filter.withKeyU16(nl.TCA_FLOWER_KEY_VLAN_ETH_TYPE, val)
}

// FlowerKey is an interface which represents packet's fields.
// Serialize used during creation of netlink message.
// Deserialize used during parsing of netlink message.
// ID returns Key's id for comparisson operations.
type FlowerKey interface {
	Serialize() []byte
	Deserialize([]byte)
	ID() int
}

func flowerKeyId2String(id int) string {
	switch id {
	case nl.TCA_FLOWER_KEY_ETH_DST:
		return "eth_dst"
	case nl.TCA_FLOWER_KEY_ETH_DST_MASK:
		return "eth_dst_mask"
	case nl.TCA_FLOWER_KEY_ETH_SRC:
		return "eth_src"
	case nl.TCA_FLOWER_KEY_ETH_SRC_MASK:
		return "eth_src_mask"
	case nl.TCA_FLOWER_KEY_ETH_TYPE:
		return "eth_type"
	case nl.TCA_FLOWER_KEY_IP_PROTO:
		return "ip_proto"
	case nl.TCA_FLOWER_KEY_VLAN_ID:
		return "vlan_id"
	case nl.TCA_FLOWER_KEY_VLAN_PRIO:
		return "vlan_prio"
	case nl.TCA_FLOWER_KEY_VLAN_ETH_TYPE:
		return "vlan_eth_type"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}

// Since many of the flower keys has same underlying data there are generic key's types,
// which can be used directly instead of With methods, but better not.

type FlowerKeyEthAddr struct {
	id   int
	addr net.HardwareAddr
}

func (k *FlowerKeyEthAddr) Serialize() []byte {
	return k.addr
}

func (k *FlowerKeyEthAddr) Deserialize(bytes []byte) {
	k.addr = bytes[0:6]
}

func (k *FlowerKeyEthAddr) ID() int {
	return k.id
}

func (k *FlowerKeyEthAddr) String() string {
	return fmt.Sprintf("%s: %s", flowerKeyId2String(k.id), k.addr)
}

type FlowerKeyU8 struct {
	id  int
	val uint8
}

func (k *FlowerKeyU8) Serialize() []byte {
	bytes := make([]byte, 1)
	bytes[0] = k.val
	return bytes
}

func (k *FlowerKeyU8) Deserialize(bytes []byte) {
	k.val = bytes[0]
}

func (k *FlowerKeyU8) ID() int {
	return k.id
}

// Return string representation of most used ip protocols
func ipProto2String(proto uint8) string {
	switch proto {
	case unix.IPPROTO_ICMP:
		return "IPPROTO_ICMP"
	case unix.IPPROTO_ICMPV6:
		return "IPPROTO_ICMPV6"
	case unix.IPPROTO_IP:
		return "IPPROTO_IPV6"
	case unix.IPPROTO_IPV6:
		return "IPPROTO_IPV6"
	case unix.IPPROTO_TCP:
		return "IPPROTO_TCP"
	case unix.IPPROTO_UDP:
		return "IPPROTO_UDP"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

func (k *FlowerKeyU8) String() string {
	if k.id != nl.TCA_FLOWER_KEY_IP_PROTO {
		return fmt.Sprintf("%s: %#x", flowerKeyId2String(k.id), k.val)
	}
	return fmt.Sprintf("%s: %s", flowerKeyId2String(k.id), ipProto2String(k.val))
}

type FlowerKeyU16 struct {
	id  int
	val uint16
}

// U16 value in network order
func (k *FlowerKeyU16) Serialize() []byte {
	return htons(k.val)
}

func (k *FlowerKeyU16) Deserialize(bytes []byte) {
	k.val = ntohs(bytes[0:2])
}

func (k *FlowerKeyU16) ID() int {
	return k.id
}

func (k *FlowerKeyU16) String() string {
	return fmt.Sprintf("%s: %#x", flowerKeyId2String(k.id), k.val)
}

// Vlan ID is 12 bit host ordered value and should be handled separately
type FlowerKeyVlanID struct {
	id  int
	val uint16
}

func (k *FlowerKeyVlanID) Serialize() []byte {
	bytes := make([]byte, 2)
	native.PutUint16(bytes, k.val)
	return bytes
}

func (k *FlowerKeyVlanID) Deserialize(bytes []byte) {
	k.val = native.Uint16(bytes[0:2])
}

func (k *FlowerKeyVlanID) ID() int {
	return k.id
}

func (k *FlowerKeyVlanID) String() string {
	return fmt.Sprintf("vlan_id: %d", k.val)
}

// FilterDel will delete a filter from the system.
// Equivalent to: `tc filter del $filter`
func FilterDel(filter Filter) error {
	return pkgHandle.FilterDel(filter)
}

// FilterDel will delete a filter from the system.
// Equivalent to: `tc filter del $filter`
func (h *Handle) FilterDel(filter Filter) error {
	req := h.newNetlinkRequest(unix.RTM_DELTFILTER, unix.NLM_F_ACK)
	base := filter.Attrs()
	msg := &nl.TcMsg{
		Family:  nl.FAMILY_ALL,
		Ifindex: int32(base.LinkIndex),
		Handle:  base.Handle,
		Parent:  base.Parent,
		Info:    MakeHandle(base.Priority, nl.Swap16(base.Protocol)),
	}
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// FilterAdd will add a filter to the system.
// Equivalent to: `tc filter add $filter`
func FilterAdd(filter Filter) error {
	return pkgHandle.FilterAdd(filter)
}

// FilterAdd will add a filter to the system.
// Equivalent to: `tc filter add $filter`
func (h *Handle) FilterAdd(filter Filter) error {
	return h.filterModify(filter, unix.NLM_F_CREATE|unix.NLM_F_EXCL)
}

// FilterReplace will replace a filter.
// Equivalent to: `tc filter replace $filter`
func FilterReplace(filter Filter) error {
	return pkgHandle.FilterReplace(filter)
}

// FilterReplace will replace a filter.
// Equivalent to: `tc filter replace $filter`
func (h *Handle) FilterReplace(filter Filter) error {
	return h.filterModify(filter, unix.NLM_F_CREATE)
}

func (h *Handle) filterModify(filter Filter, flags int) error {
	native = nl.NativeEndian()
	req := h.newNetlinkRequest(unix.RTM_NEWTFILTER, flags|unix.NLM_F_ACK)
	base := filter.Attrs()
	msg := &nl.TcMsg{
		Family:  nl.FAMILY_ALL,
		Ifindex: int32(base.LinkIndex),
		Handle:  base.Handle,
		Parent:  base.Parent,
		Info:    MakeHandle(base.Priority, nl.Swap16(base.Protocol)),
	}
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.TCA_KIND, nl.ZeroTerminated(filter.Type())))

	options := nl.NewRtAttr(nl.TCA_OPTIONS, nil)

	switch filter := filter.(type) {
	case *U32:
		sel := filter.Sel
		if sel == nil {
			// match all
			sel = &nl.TcU32Sel{
				Nkeys: 1,
				Flags: nl.TC_U32_TERMINAL,
			}
			sel.Keys = append(sel.Keys, nl.TcU32Key{})
		}

		if native != networkOrder {
			// Copy TcU32Sel.
			cSel := *sel
			keys := make([]nl.TcU32Key, cap(sel.Keys))
			copy(keys, sel.Keys)
			cSel.Keys = keys
			sel = &cSel

			// Handle the endianness of attributes
			sel.Offmask = native.Uint16(htons(sel.Offmask))
			sel.Hmask = native.Uint32(htonl(sel.Hmask))
			for i, key := range sel.Keys {
				sel.Keys[i].Mask = native.Uint32(htonl(key.Mask))
				sel.Keys[i].Val = native.Uint32(htonl(key.Val))
			}
		}
		sel.Nkeys = uint8(len(sel.Keys))
		options.AddRtAttr(nl.TCA_U32_SEL, sel.Serialize())
		if filter.ClassId != 0 {
			options.AddRtAttr(nl.TCA_U32_CLASSID, nl.Uint32Attr(filter.ClassId))
		}
		if filter.Divisor != 0 {
			if (filter.Divisor-1)&filter.Divisor != 0 {
				return fmt.Errorf("illegal divisor %d. Must be a power of 2", filter.Divisor)
			}
			options.AddRtAttr(nl.TCA_U32_DIVISOR, nl.Uint32Attr(filter.Divisor))
		}
		if filter.Hash != 0 {
			options.AddRtAttr(nl.TCA_U32_HASH, nl.Uint32Attr(filter.Hash))
		}
		actionsAttr := options.AddRtAttr(nl.TCA_U32_ACT, nil)
		// backwards compatibility
		if filter.RedirIndex != 0 {
			filter.Actions = append([]Action{NewMirredAction(filter.RedirIndex)}, filter.Actions...)
		}
		if err := EncodeActions(actionsAttr, filter.Actions); err != nil {
			return err
		}
	case *Fw:
		if filter.Mask != 0 {
			b := make([]byte, 4)
			native.PutUint32(b, filter.Mask)
			options.AddRtAttr(nl.TCA_FW_MASK, b)
		}
		if filter.InDev != "" {
			options.AddRtAttr(nl.TCA_FW_INDEV, nl.ZeroTerminated(filter.InDev))
		}
		if (filter.Police != nl.TcPolice{}) {

			police := options.AddRtAttr(nl.TCA_FW_POLICE, nil)
			police.AddRtAttr(nl.TCA_POLICE_TBF, filter.Police.Serialize())
			if (filter.Police.Rate != nl.TcRateSpec{}) {
				payload := SerializeRtab(filter.Rtab)
				police.AddRtAttr(nl.TCA_POLICE_RATE, payload)
			}
			if (filter.Police.PeakRate != nl.TcRateSpec{}) {
				payload := SerializeRtab(filter.Ptab)
				police.AddRtAttr(nl.TCA_POLICE_PEAKRATE, payload)
			}
		}
		if filter.ClassId != 0 {
			b := make([]byte, 4)
			native.PutUint32(b, filter.ClassId)
			options.AddRtAttr(nl.TCA_FW_CLASSID, b)
		}
	case *BpfFilter:
		var bpfFlags uint32
		if filter.ClassId != 0 {
			options.AddRtAttr(nl.TCA_BPF_CLASSID, nl.Uint32Attr(filter.ClassId))
		}
		if filter.Fd >= 0 {
			options.AddRtAttr(nl.TCA_BPF_FD, nl.Uint32Attr((uint32(filter.Fd))))
		}
		if filter.Name != "" {
			options.AddRtAttr(nl.TCA_BPF_NAME, nl.ZeroTerminated(filter.Name))
		}
		if filter.DirectAction {
			bpfFlags |= nl.TCA_BPF_FLAG_ACT_DIRECT
		}
		options.AddRtAttr(nl.TCA_BPF_FLAGS, nl.Uint32Attr(bpfFlags))
	case *MatchAll:
		actionsAttr := options.AddRtAttr(nl.TCA_MATCHALL_ACT, nil)
		if err := EncodeActions(actionsAttr, filter.Actions); err != nil {
			return err
		}
		if filter.ClassId != 0 {
			options.AddRtAttr(nl.TCA_MATCHALL_CLASSID, nl.Uint32Attr(filter.ClassId))
		}
	case *Flower:
		if filter.ClassId != 0 {
			options.AddRtAttr(nl.TCA_FLOWER_CLASSID, nl.Uint32Attr(filter.ClassId))
		}

		if filter.Protocol != unix.ETH_P_ALL {
			options.AddRtAttr(nl.TCA_FLOWER_KEY_ETH_TYPE, htons(filter.Protocol))
		}

		if filter.Flags&^nl.TCA_CLS_FLAGS_INPUT_MASK != 0 {
			return fmt.Errorf("not allowed flags for flower classifier")
		}
		options.AddRtAttr(nl.TCA_FLOWER_FLAGS, nl.Uint32Attr(filter.Flags))

		if err := parseFlowerFilterKeys(options, filter); err != nil {
			return err
		}

		actionsAttr := options.AddRtAttr(nl.TCA_FLOWER_ACT, nil)
		if err := EncodeActions(actionsAttr, filter.Actions); err != nil {
			return err
		}
	}

	req.AddData(options)
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func parseFlowerFilterKeys(options *nl.RtAttr, filter *Flower) error {
	// Iterate over all keys to keep order
	for i := nl.TCA_FLOWER_KEY_ETH_DST; i <= nl.TCA_FLOWER_KEY_MPLS_OPTS; i++ {
		key, exist := filter.Keys[i]
		if !exist {
			continue
		}
		// Validate values first
		switch i {
		case nl.TCA_FLOWER_KEY_ETH_DST,
			nl.TCA_FLOWER_KEY_ETH_DST_MASK,
			nl.TCA_FLOWER_KEY_ETH_SRC,
			nl.TCA_FLOWER_KEY_ETH_SRC_MASK:
			ethKey, _ := key.(*FlowerKeyEthAddr)
			if len(ethKey.addr) != 6 {
				return fmt.Errorf("expected 6 byte len address - have %s", ethKey)
			}
		case nl.TCA_FLOWER_KEY_VLAN_ID:
			vlanId, _ := key.(*FlowerKeyVlanID)
			if vlanId.val&^0xfff != 0 {
				return fmt.Errorf("vlan id isn't a 12bit value.")
			}
			if filter.Protocol != unix.ETH_P_8021AD && filter.Protocol != unix.ETH_P_8021Q {
				return fmt.Errorf("can't set vlan id if filter protocol isn't 802.1Q or 802.1AD")
			}
		case nl.TCA_FLOWER_KEY_VLAN_PRIO:
			vlanPrio, _ := key.(*FlowerKeyU8)
			if vlanPrio.val&^0x7 != 0 {
				return fmt.Errorf("vlan prio isn't a 3bit value.")
			}
			fallthrough
		case nl.TCA_FLOWER_KEY_VLAN_ETH_TYPE:
			if filter.Protocol != unix.ETH_P_8021AD && filter.Protocol != unix.ETH_P_8021Q {
				return fmt.Errorf("can't set vlan prio/ethtype if rotocol isn't 802.1Q or 802.1AD")
			}
		}
		options.AddRtAttr(i, key.Serialize())
	}
	return nil
}

// FilterList gets a list of filters in the system.
// Equivalent to: `tc filter show`.
// Generally returns nothing if link and parent are not specified.
func FilterList(link Link, parent uint32) ([]Filter, error) {
	return pkgHandle.FilterList(link, parent)
}

// FilterList gets a list of filters in the system.
// Equivalent to: `tc filter show`.
// Generally returns nothing if link and parent are not specified.
func (h *Handle) FilterList(link Link, parent uint32) ([]Filter, error) {
	req := h.newNetlinkRequest(unix.RTM_GETTFILTER, unix.NLM_F_DUMP)
	msg := &nl.TcMsg{
		Family: nl.FAMILY_ALL,
		Parent: parent,
	}
	if link != nil {
		base := link.Attrs()
		h.ensureIndex(base)
		msg.Ifindex = int32(base.Index)
	}
	req.AddData(msg)

	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWTFILTER)
	if err != nil {
		return nil, err
	}

	var res []Filter
	for _, m := range msgs {
		msg := nl.DeserializeTcMsg(m)

		attrs, err := nl.ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		base := FilterAttrs{
			LinkIndex: int(msg.Ifindex),
			Handle:    msg.Handle,
			Parent:    msg.Parent,
		}
		base.Priority, base.Protocol = MajorMinor(msg.Info)
		base.Protocol = nl.Swap16(base.Protocol)

		var filter Filter
		filterType := ""
		detailed := false
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case nl.TCA_KIND:
				filterType = string(attr.Value[:len(attr.Value)-1])
				switch filterType {
				case "u32":
					filter = &U32{}
				case "fw":
					filter = &Fw{}
				case "bpf":
					filter = &BpfFilter{}
				case "matchall":
					filter = &MatchAll{}
				case "flower":
					filter = &Flower{}
				default:
					filter = &GenericFilter{FilterType: filterType}
				}
			case nl.TCA_OPTIONS:
				data, err := nl.ParseRouteAttr(attr.Value)
				if err != nil {
					return nil, err
				}
				switch filterType {
				case "u32":
					detailed, err = parseU32Data(filter, data)
					if err != nil {
						return nil, err
					}
				case "fw":
					detailed, err = parseFwData(filter, data)
					if err != nil {
						return nil, err
					}
				case "bpf":
					detailed, err = parseBpfData(filter, data)
					if err != nil {
						return nil, err
					}
				case "matchall":
					detailed, err = parseMatchAllData(filter, data)
					if err != nil {
						return nil, err
					}
				case "flower":
					detailed, err = parseFlowerData(filter, data)
					if err != nil {
						return nil, err
					}
				default:
					detailed = true
				}
			}
		}
		// only return the detailed version of the filter
		if detailed {
			*filter.Attrs() = base
			res = append(res, filter)
		}
	}

	return res, nil
}

func toTcGen(attrs *ActionAttrs, tcgen *nl.TcGen) {
	tcgen.Index = uint32(attrs.Index)
	tcgen.Capab = uint32(attrs.Capab)
	tcgen.Action = int32(attrs.Action)
	tcgen.Refcnt = int32(attrs.Refcnt)
	tcgen.Bindcnt = int32(attrs.Bindcnt)
}

func toAttrs(tcgen *nl.TcGen, attrs *ActionAttrs) {
	attrs.Index = int(tcgen.Index)
	attrs.Capab = int(tcgen.Capab)
	attrs.Action = TcAct(tcgen.Action)
	attrs.Refcnt = int(tcgen.Refcnt)
	attrs.Bindcnt = int(tcgen.Bindcnt)
}

func EncodeActions(attr *nl.RtAttr, actions []Action) error {
	tabIndex := int(nl.TCA_ACT_TAB)

	for _, action := range actions {
		switch action := action.(type) {
		default:
			return fmt.Errorf("unknown action type %s", action.Type())
		case *MirredAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("mirred"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			mirred := nl.TcMirred{
				Eaction: int32(action.MirredAction),
				Ifindex: uint32(action.Ifindex),
			}
			toTcGen(action.Attrs(), &mirred.TcGen)
			aopts.AddRtAttr(nl.TCA_MIRRED_PARMS, mirred.Serialize())
		case *TunnelKeyAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("tunnel_key"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			tun := nl.TcTunnelKey{
				Action: int32(action.Action),
			}
			toTcGen(action.Attrs(), &tun.TcGen)
			aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_PARMS, tun.Serialize())
			if action.Action == TCA_TUNNEL_KEY_SET {
				aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_ENC_KEY_ID, htonl(action.KeyID))
				if v4 := action.SrcAddr.To4(); v4 != nil {
					aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_ENC_IPV4_SRC, v4[:])
				} else if v6 := action.SrcAddr.To16(); v6 != nil {
					aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_ENC_IPV6_SRC, v6[:])
				} else {
					return fmt.Errorf("invalid src addr %s for tunnel_key action", action.SrcAddr)
				}
				if v4 := action.DstAddr.To4(); v4 != nil {
					aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_ENC_IPV4_DST, v4[:])
				} else if v6 := action.DstAddr.To16(); v6 != nil {
					aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_ENC_IPV6_DST, v6[:])
				} else {
					return fmt.Errorf("invalid dst addr %s for tunnel_key action", action.DstAddr)
				}
				if action.DestPort != 0 {
					aopts.AddRtAttr(nl.TCA_TUNNEL_KEY_ENC_DST_PORT, htons(action.DestPort))
				}
			}
		case *SkbEditAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("skbedit"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			skbedit := nl.TcSkbEdit{}
			toTcGen(action.Attrs(), &skbedit.TcGen)
			aopts.AddRtAttr(nl.TCA_SKBEDIT_PARMS, skbedit.Serialize())
			if action.QueueMapping != nil {
				aopts.AddRtAttr(nl.TCA_SKBEDIT_QUEUE_MAPPING, nl.Uint16Attr(*action.QueueMapping))
			}
			if action.Priority != nil {
				aopts.AddRtAttr(nl.TCA_SKBEDIT_PRIORITY, nl.Uint32Attr(*action.Priority))
			}
			if action.PType != nil {
				aopts.AddRtAttr(nl.TCA_SKBEDIT_PTYPE, nl.Uint16Attr(*action.PType))
			}
			if action.Mark != nil {
				aopts.AddRtAttr(nl.TCA_SKBEDIT_MARK, nl.Uint32Attr(*action.Mark))
			}
		case *ConnmarkAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("connmark"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			connmark := nl.TcConnmark{
				Zone: action.Zone,
			}
			toTcGen(action.Attrs(), &connmark.TcGen)
			aopts.AddRtAttr(nl.TCA_CONNMARK_PARMS, connmark.Serialize())
		case *BpfAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("bpf"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			gen := nl.TcGen{}
			toTcGen(action.Attrs(), &gen)
			aopts.AddRtAttr(nl.TCA_ACT_BPF_PARMS, gen.Serialize())
			aopts.AddRtAttr(nl.TCA_ACT_BPF_FD, nl.Uint32Attr(uint32(action.Fd)))
			aopts.AddRtAttr(nl.TCA_ACT_BPF_NAME, nl.ZeroTerminated(action.Name))
		case *VlanAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("vlan"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			vlan := nl.TcVlan{
				Action: int32(action.VlanAction),
			}
			toTcGen(action.Attrs(), &vlan.TcGen)
			aopts.AddRtAttr(nl.TCA_VLAN_PARMS, vlan.Serialize())
			// Ignore VLAN_{ID,PROTO,PRIO} if action is VLAN_POP
			if action.VlanAction != TCA_VLAN_ACT_POP {
				aopts.AddRtAttr(nl.TCA_VLAN_PUSH_VLAN_ID, nl.Uint16Attr(action.Id))
				if action.Proto != 0 && action.Proto != unix.ETH_P_8021AD && action.Proto != unix.ETH_P_8021Q {
					return fmt.Errorf("protocol %x is not supported", action.Proto)
				}
				if action.Proto != 0 {
					// Should be in network order
					aopts.AddRtAttr(nl.TCA_VLAN_PUSH_VLAN_PROTOCOL, htons(action.Proto))
				}
				aopts.AddRtAttr(nl.TCA_VLAN_PUSH_VLAN_PRIORITY, nl.Uint8Attr(action.Prio))
			}
		case *GenericAction:
			table := attr.AddRtAttr(tabIndex, nil)
			tabIndex++
			table.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("gact"))
			aopts := table.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)
			gen := nl.TcGen{}
			toTcGen(action.Attrs(), &gen)
			aopts.AddRtAttr(nl.TCA_GACT_PARMS, gen.Serialize())
		}
	}
	return nil
}

func parseActions(tables []syscall.NetlinkRouteAttr) ([]Action, error) {
	var actions []Action
	for _, table := range tables {
		var action Action
		var actionType string
		aattrs, err := nl.ParseRouteAttr(table.Value)
		if err != nil {
			return nil, err
		}
	nextattr:
		for _, aattr := range aattrs {
			switch aattr.Attr.Type {
			case nl.TCA_KIND:
				actionType = string(aattr.Value[:len(aattr.Value)-1])
				// only parse if the action is mirred or bpf
				switch actionType {
				case "mirred":
					action = &MirredAction{}
				case "bpf":
					action = &BpfAction{}
				case "connmark":
					action = &ConnmarkAction{}
				case "gact":
					action = &GenericAction{}
				case "tunnel_key":
					action = &TunnelKeyAction{}
				case "skbedit":
					action = &SkbEditAction{}
				case "vlan":
					action = &VlanAction{}
				default:
					break nextattr
				}
			case nl.TCA_OPTIONS:
				adata, err := nl.ParseRouteAttr(aattr.Value)
				if err != nil {
					return nil, err
				}
				for _, adatum := range adata {
					switch actionType {
					case "mirred":
						switch adatum.Attr.Type {
						case nl.TCA_MIRRED_PARMS:
							mirred := *nl.DeserializeTcMirred(adatum.Value)
							action.(*MirredAction).ActionAttrs = ActionAttrs{}
							toAttrs(&mirred.TcGen, action.Attrs())
							action.(*MirredAction).Ifindex = int(mirred.Ifindex)
							action.(*MirredAction).MirredAction = MirredAct(mirred.Eaction)
						}
					case "tunnel_key":
						switch adatum.Attr.Type {
						case nl.TCA_TUNNEL_KEY_PARMS:
							tun := *nl.DeserializeTunnelKey(adatum.Value)
							action.(*TunnelKeyAction).ActionAttrs = ActionAttrs{}
							toAttrs(&tun.TcGen, action.Attrs())
							action.(*TunnelKeyAction).Action = TunnelKeyAct(tun.Action)
						case nl.TCA_TUNNEL_KEY_ENC_KEY_ID:
							action.(*TunnelKeyAction).KeyID = networkOrder.Uint32(adatum.Value[0:4])
						case nl.TCA_TUNNEL_KEY_ENC_IPV6_SRC, nl.TCA_TUNNEL_KEY_ENC_IPV4_SRC:
							action.(*TunnelKeyAction).SrcAddr = adatum.Value[:]
						case nl.TCA_TUNNEL_KEY_ENC_IPV6_DST, nl.TCA_TUNNEL_KEY_ENC_IPV4_DST:
							action.(*TunnelKeyAction).DstAddr = adatum.Value[:]
						case nl.TCA_TUNNEL_KEY_ENC_DST_PORT:
							action.(*TunnelKeyAction).DestPort = ntohs(adatum.Value)
						}
					case "skbedit":
						switch adatum.Attr.Type {
						case nl.TCA_SKBEDIT_PARMS:
							skbedit := *nl.DeserializeSkbEdit(adatum.Value)
							action.(*SkbEditAction).ActionAttrs = ActionAttrs{}
							toAttrs(&skbedit.TcGen, action.Attrs())
						case nl.TCA_SKBEDIT_MARK:
							mark := native.Uint32(adatum.Value[0:4])
							action.(*SkbEditAction).Mark = &mark
						case nl.TCA_SKBEDIT_PRIORITY:
							priority := native.Uint32(adatum.Value[0:4])
							action.(*SkbEditAction).Priority = &priority
						case nl.TCA_SKBEDIT_PTYPE:
							ptype := native.Uint16(adatum.Value[0:2])
							action.(*SkbEditAction).PType = &ptype
						case nl.TCA_SKBEDIT_QUEUE_MAPPING:
							mapping := native.Uint16(adatum.Value[0:2])
							action.(*SkbEditAction).QueueMapping = &mapping
						}
					case "bpf":
						switch adatum.Attr.Type {
						case nl.TCA_ACT_BPF_PARMS:
							gen := *nl.DeserializeTcGen(adatum.Value)
							toAttrs(&gen, action.Attrs())
						case nl.TCA_ACT_BPF_FD:
							action.(*BpfAction).Fd = int(native.Uint32(adatum.Value[0:4]))
						case nl.TCA_ACT_BPF_NAME:
							action.(*BpfAction).Name = string(adatum.Value[:len(adatum.Value)-1])
						}
					case "connmark":
						switch adatum.Attr.Type {
						case nl.TCA_CONNMARK_PARMS:
							connmark := *nl.DeserializeTcConnmark(adatum.Value)
							action.(*ConnmarkAction).ActionAttrs = ActionAttrs{}
							toAttrs(&connmark.TcGen, action.Attrs())
							action.(*ConnmarkAction).Zone = connmark.Zone
						}
					case "gact":
						switch adatum.Attr.Type {
						case nl.TCA_GACT_PARMS:
							gen := *nl.DeserializeTcGen(adatum.Value)
							toAttrs(&gen, action.Attrs())
						}
					case "vlan":
						switch adatum.Attr.Type {
						case nl.TCA_VLAN_PARMS:
							vlan := *nl.DeserializeTcVlan(adatum.Value)
							toAttrs(&vlan.TcGen, action.Attrs())
							action.(*VlanAction).VlanAction = VlanAct(vlan.Action)
						case nl.TCA_VLAN_PUSH_VLAN_ID:
							action.(*VlanAction).Id = native.Uint16(adatum.Value[0:2])
						case nl.TCA_VLAN_PUSH_VLAN_PROTOCOL:
							// Value in network order
							action.(*VlanAction).Proto = ntohs(adatum.Value[0:2])
						case nl.TCA_VLAN_PUSH_VLAN_PRIORITY:
							action.(*VlanAction).Prio = uint8(adatum.Value[0:1][0])
						}
					}
				}
			}
		}
		actions = append(actions, action)
	}
	return actions, nil
}

func parseU32Data(filter Filter, data []syscall.NetlinkRouteAttr) (bool, error) {
	native = nl.NativeEndian()
	u32 := filter.(*U32)
	detailed := false
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_U32_SEL:
			detailed = true
			sel := nl.DeserializeTcU32Sel(datum.Value)
			u32.Sel = sel
			if native != networkOrder {
				// Handle the endianness of attributes
				u32.Sel.Offmask = native.Uint16(htons(sel.Offmask))
				u32.Sel.Hmask = native.Uint32(htonl(sel.Hmask))
				for i, key := range u32.Sel.Keys {
					u32.Sel.Keys[i].Mask = native.Uint32(htonl(key.Mask))
					u32.Sel.Keys[i].Val = native.Uint32(htonl(key.Val))
				}
			}
		case nl.TCA_U32_ACT:
			tables, err := nl.ParseRouteAttr(datum.Value)
			if err != nil {
				return detailed, err
			}
			u32.Actions, err = parseActions(tables)
			if err != nil {
				return detailed, err
			}
			for _, action := range u32.Actions {
				if action, ok := action.(*MirredAction); ok {
					u32.RedirIndex = int(action.Ifindex)
				}
			}
		case nl.TCA_U32_CLASSID:
			u32.ClassId = native.Uint32(datum.Value)
		case nl.TCA_U32_DIVISOR:
			u32.Divisor = native.Uint32(datum.Value)
		case nl.TCA_U32_HASH:
			u32.Hash = native.Uint32(datum.Value)
		}
	}
	return detailed, nil
}

func parseFwData(filter Filter, data []syscall.NetlinkRouteAttr) (bool, error) {
	native = nl.NativeEndian()
	fw := filter.(*Fw)
	detailed := true
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_FW_MASK:
			fw.Mask = native.Uint32(datum.Value[0:4])
		case nl.TCA_FW_CLASSID:
			fw.ClassId = native.Uint32(datum.Value[0:4])
		case nl.TCA_FW_INDEV:
			fw.InDev = string(datum.Value[:len(datum.Value)-1])
		case nl.TCA_FW_POLICE:
			adata, _ := nl.ParseRouteAttr(datum.Value)
			for _, aattr := range adata {
				switch aattr.Attr.Type {
				case nl.TCA_POLICE_TBF:
					fw.Police = *nl.DeserializeTcPolice(aattr.Value)
				case nl.TCA_POLICE_RATE:
					fw.Rtab = DeserializeRtab(aattr.Value)
				case nl.TCA_POLICE_PEAKRATE:
					fw.Ptab = DeserializeRtab(aattr.Value)
				}
			}
		}
	}
	return detailed, nil
}

func parseBpfData(filter Filter, data []syscall.NetlinkRouteAttr) (bool, error) {
	native = nl.NativeEndian()
	bpf := filter.(*BpfFilter)
	detailed := true
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_BPF_FD:
			bpf.Fd = int(native.Uint32(datum.Value[0:4]))
		case nl.TCA_BPF_NAME:
			bpf.Name = string(datum.Value[:len(datum.Value)-1])
		case nl.TCA_BPF_CLASSID:
			bpf.ClassId = native.Uint32(datum.Value[0:4])
		case nl.TCA_BPF_FLAGS:
			flags := native.Uint32(datum.Value[0:4])
			if (flags & nl.TCA_BPF_FLAG_ACT_DIRECT) != 0 {
				bpf.DirectAction = true
			}
		case nl.TCA_BPF_ID:
			bpf.Id = int(native.Uint32(datum.Value[0:4]))
		case nl.TCA_BPF_TAG:
			bpf.Tag = hex.EncodeToString(datum.Value[:len(datum.Value)-1])
		}
	}
	return detailed, nil
}

func parseMatchAllData(filter Filter, data []syscall.NetlinkRouteAttr) (bool, error) {
	native = nl.NativeEndian()
	matchall := filter.(*MatchAll)
	detailed := true
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_MATCHALL_CLASSID:
			matchall.ClassId = native.Uint32(datum.Value[0:4])
		case nl.TCA_MATCHALL_ACT:
			tables, err := nl.ParseRouteAttr(datum.Value)
			if err != nil {
				return detailed, err
			}
			matchall.Actions, err = parseActions(tables)
			if err != nil {
				return detailed, err
			}
		}
	}
	return detailed, nil
}

func parseFlowerData(filter Filter, data []syscall.NetlinkRouteAttr) (bool, error) {
	native = nl.NativeEndian()
	flower := filter.(*Flower)
	flower.Keys = make(map[int]FlowerKey)
	detailed := true
	for _, datum := range data {
		id := int(datum.Attr.Type)
		switch id {
		case nl.TCA_FLOWER_CLASSID:
			flower.ClassId = native.Uint32(datum.Value[0:4])
		case nl.TCA_FLOWER_FLAGS:
			flower.Flags = native.Uint32(datum.Value[0:4])
		case nl.TCA_FLOWER_KEY_ETH_DST,
			nl.TCA_FLOWER_KEY_ETH_DST_MASK,
			nl.TCA_FLOWER_KEY_ETH_SRC,
			nl.TCA_FLOWER_KEY_ETH_SRC_MASK:
			flower.Keys[id] = &FlowerKeyEthAddr{id: id}
			flower.Keys[id].Deserialize(datum.Value)
		case nl.TCA_FLOWER_KEY_IP_PROTO,
			nl.TCA_FLOWER_KEY_VLAN_PRIO:
			flower.Keys[id] = &FlowerKeyU8{id: id}
			flower.Keys[id].Deserialize(datum.Value)
		case nl.TCA_FLOWER_KEY_VLAN_ID:
			flower.Keys[id] = &FlowerKeyVlanID{id: id}
			flower.Keys[id].Deserialize(datum.Value)
		case nl.TCA_FLOWER_KEY_ETH_TYPE,
			nl.TCA_FLOWER_KEY_VLAN_ETH_TYPE:
			flower.Keys[id] = &FlowerKeyU16{id: id}
			flower.Keys[id].Deserialize(datum.Value)
		case nl.TCA_FLOWER_ACT:
			tables, err := nl.ParseRouteAttr(datum.Value)
			if err != nil {
				return detailed, err
			}
			flower.Actions, err = parseActions(tables)
			if err != nil {
				return detailed, err
			}
		}
	}
	return detailed, nil
}

func AlignToAtm(size uint) uint {
	var linksize, cells int
	cells = int(size / nl.ATM_CELL_PAYLOAD)
	if (size % nl.ATM_CELL_PAYLOAD) > 0 {
		cells++
	}
	linksize = cells * nl.ATM_CELL_SIZE
	return uint(linksize)
}

func AdjustSize(sz uint, mpu uint, linklayer int) uint {
	if sz < mpu {
		sz = mpu
	}
	switch linklayer {
	case nl.LINKLAYER_ATM:
		return AlignToAtm(sz)
	default:
		return sz
	}
}

func CalcRtable(rate *nl.TcRateSpec, rtab []uint32, cellLog int, mtu uint32, linklayer int) int {
	bps := rate.Rate
	mpu := rate.Mpu
	var sz uint
	if mtu == 0 {
		mtu = 2047
	}
	if cellLog < 0 {
		cellLog = 0
		for (mtu >> uint(cellLog)) > 255 {
			cellLog++
		}
	}
	for i := 0; i < 256; i++ {
		sz = AdjustSize(uint((i+1)<<uint32(cellLog)), uint(mpu), linklayer)
		rtab[i] = Xmittime(uint64(bps), uint32(sz))
	}
	rate.CellAlign = -1
	rate.CellLog = uint8(cellLog)
	rate.Linklayer = uint8(linklayer & nl.TC_LINKLAYER_MASK)
	return cellLog
}

func DeserializeRtab(b []byte) [256]uint32 {
	var rtab [256]uint32
	native := nl.NativeEndian()
	r := bytes.NewReader(b)
	_ = binary.Read(r, native, &rtab)
	return rtab
}

func SerializeRtab(rtab [256]uint32) []byte {
	native := nl.NativeEndian()
	var w bytes.Buffer
	_ = binary.Write(&w, native, rtab)
	return w.Bytes()
}

func ethAddrMask() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}
