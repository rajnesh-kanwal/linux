#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from ctypes import *
import json
import argparse

class DAFirmwareHeader(Structure):

    """
    struct da_firmware_hdr {
        __u32 major_ver, minor_ver;
        __u32 count;
        __u8 type;
        __u8 rsvd[7];
    }
    """
    _pack_ = 1
    _fields_ = [
        ('major_ver',         c_uint32),
        ('minor_ver',         c_uint32),
        ('count',             c_uint32),
        ('type',              c_uint8),
        ('rsvd',              c_uint8 * 7),
    ]

    def update(self, obj={}):
        for k, v in obj.items():
            if v:
                setattr(self, k, int(v))

        setattr(self, "rsvd",  (0, 0, 0, 0, 0, 0, 0))

    def __repr__(self):
        return "version:%d.%d count: %d type: %d rsvd:%s" % (self.major_ver, self.minor_ver, self.count, self.type, self.rsvd[0:7])


class DABusHeader(Structure):

    """
    struct da_bus_hdr {
        char bus[NAME_LEN];
        __u32 count;
    }
    """
    _pack_ = 1
    _fields_ = [
        ('bus',           c_char * 64),
        ('count',         c_uint32),
    ]

    def update(self, obj={}):
        for k, v in obj.items():
            if v:
                if k == "bus":
                    setattr(self, k, v.encode('utf-8'))
                elif k == "count":
                    setattr(self, k, int(v))
                elif k == "devices":
                    setattr(self, "count", int(len(v)))

    def __repr__(self):
        return "bus: %s count: %d" % (self.bus.decode(), self.count)

class DAPCIDeviceId(Structure):

    """
    struct da_pci_device_id {
        __u32 vendor, device;           /* Vendor and device ID or PCI_ANY_ID*/
        __u32 subvendor, subdevice;     /* Subsystem ID's or PCI_ANY_ID */
        __u32 class, class_mask;        /* (class,subclass,prog-if) triplet */
    }

    """
    _pack_ = 1
    _fields_ = [
        ('vendor',        c_uint32),
        ('device',        c_uint32),
        ('subvendor',     c_uint32),
        ('subdevice',     c_uint32),
        ('class',         c_uint32),
        ('class_mask',    c_uint32),
    ]

    def update(self, obj={}):
        for field in ['vendor', 'device', 'subvendor', 'subdevice']:
            setattr(self, field, 0xffffffff)
        for field in ['class', 'class_mask']:
            setattr(self, field, 0)
        for k, v in obj.items():
            if v:
                setattr(self, k, int(v, 16))

    def __repr__(self):
        return "dev %x:%x sub %x:%x" % (self.vendor, self.device,
                self.subvendor, self.subdevice)


class DABusDeviceID(Structure):

    """
    struct da_bus_device_id {
        char name[NAME_LEN];
    }

    """
    _pack_ = 1
    _fields_ = [
        ('name',          c_char * 64),
    ]

    def update(self, obj={}):
        for k, v in obj.items():
            if v:
                setattr(self, k, v.encode('utf-8'))

    def __repr__(self):
        return "dev: %s" % (self.name.decode())

def JsonToStruct(data):
    obj_list=[]
    bus_count = 0
    fhdr = DAFirmwareHeader()
    for obj in data:
        if 'major_ver' in obj:
            fhdr.update(obj)
        if 'bus' in obj:
            hdr = DABusHeader()
            hdr.update(obj)
            bus_count = bus_count +  1
            obj_list.append(hdr)
            if obj['bus'] == 'pci':
                if "devices" in obj.keys():
                    for dev in obj['devices'][0:hdr.count]:
                        pci_id = DAPCIDeviceId()
                        pci_id.update(dev)
                        obj_list.append(pci_id)
            else:
                if "devices" in obj.keys():
                    for dev in obj['devices'][0:hdr.count]:
                        gen_id = DABusDeviceID()
                        gen_id.update(dev)
                        obj_list.append(gen_id)

    fhdr.count = bus_count
    obj_list.insert(0, fhdr)

    return obj_list

def main():
    parser = argparse.ArgumentParser(description="Create device filter firmware")
    parser.add_argument('--input', type=argparse.FileType('r'))
    parser.add_argument('--output', type=argparse.FileType('wb'))
    args = parser.parse_args()
    if args.input is not None:
        data = json.load(args.input)
        # Convert json file to device filter firmware
        if args.output is not None:
            obj_list = JsonToStruct(data)
            for item in obj_list:
                print(item)
                args.output.write(item)

main()
