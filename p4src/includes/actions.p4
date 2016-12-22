/*<This file is part of NDN.p4,i.e., an NDN implementation written in P4.>
Copyright (C) 2016, the University of Luxembourg
Salvatore Signorello <salvatore.signorello@uni.lu>

NDN.p4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NDN.p4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NDN.p4.  If not, see <http://www.gnu.org/licenses/>.
*/
register pit_r{
  width : 16;
  static : pit_table;
  instance_count : 65536;
}

action set_egr(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
    modify_field(flow_metadata.hasFIBentry,1);
}

action storeNumOfComponents(total) {
    modify_field(name_metadata.components,total); 
}

action computeStoreTablesIndex() {
    // watch out: if you use 0 as last parameter (size),
    // you will end up with undefined behavior for the operation (hash % 0)
    modify_field_with_hash_based_offset(name_metadata.name_hash, 0,name_hash, 65536);
    computeNameHashes();
}

action computeNameHashes() {
    modify_field_with_hash_based_offset(comp_metadata.c1, 0, chash1, 65536);
    modify_field_with_hash_based_offset(comp_metadata.c2, 0, chash2, 65536);
    modify_field_with_hash_based_offset(comp_metadata.c3, 0, chash3, 65536);
    modify_field_with_hash_based_offset(comp_metadata.c4, 0, chash4, 65536);
}

action _drop() {
    drop();
}

action readPitEntry() {
    readPit();
}

action cleanPitEntry() {
    readPit();
    register_write (pit_r,0x00,name_metadata.name_hash);
}

action readPit() {
    register_read (flow_metadata.isInPIT, pit_r, name_metadata.name_hash);
}

action updatePit_entry(){
    // AND the actual iface list with the ingress port to check if the the router has already received a similar packet from the same incoming iface (this tmp value is not used yet)
    modify_field(pit_metadata.tmp, flow_metadata.isInPIT & (1 << standard_metadata.ingress_port));
    // update the iface list to store the new iface
    modify_field(flow_metadata.isInPIT, flow_metadata.isInPIT | (1 << standard_metadata.ingress_port));
    register_write(pit_r, name_metadata.name_hash, flow_metadata.isInPIT); 
}

action setOutputIface(out_iface) {
    // I have the interfaces stored as mask of bit in flow_metadata.isInPIT, then I'll instrument the compiler to decode this mask of bit and replicate as many packets as necessary
    // modify_field(standard_metadata.egress_spec, flow_metadata.isInPIT);
    // currently hard-coded values limited to 8 output interfaces - from 0 to 7
    modify_field(standard_metadata.egress_spec, out_iface);
}

action rewrite_macs(dmac, smac) {
    modify_field(ethernet.dstAddr, dmac);
    modify_field(ethernet.srcAddr, smac);
}
