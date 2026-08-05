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
// Define for the encoding of the Length field of a TLV block
#define ENCODING_2BYTE         0xFD
#define ENCODING_4BYTE         0xFE
#define ENCODING_8BYTE         0xFF

// Define for ethertype and NDN type codes
#define ETHERTYPE_NDN          0x8624 // code used by the NFD daemon
#define NDNTYPE_INT	       0x05 
#define NDNTYPE_DAT	       0x06 
#define NDNTYPE_NAM	       0x07 
#define NDNTYPE_COM	       0x08 
#define NDNTYPE_IS2	       0x01 
#define NDNTYPE_SEL	       0x09 
#define NDNTYPE_NON	       0x0a 
#define NDNTYPE_LIF	       0x0c
#define NDNTYPE_MTI	       0x14 
#define NDNTYPE_MIN	       0x0d 
#define NDNTYPE_MAX	       0x0e 
#define NDNTYPE_PKL	       0x0f 
#define NDNTYPE_EXC	       0x10 
#define NDNTYPE_CHS	       0x11 
#define NDNTYPE_MBF	       0x12 
#define NDNTYPE_DIG	       0x1d 
#define NDNTYPE_ANY            0x13
#define NDNTYPE_CNT	       0x18
#define NDNTYPE_FRP	       0x19
#define NDNTYPE_FBI	       0x1a
#define NDNTYPE_CON	       0x15
#define NDNTYPE_KYL	       0x1c
#define NDNTYPE_SIG	       0x16
#define NDNTYPE_SGV	       0x17

#define MAX_NAME_COMPONENTS 5

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.etherType, current(0,8)) {
        0x862450 mask 0xffffff : parse_ndn_lp;
        0x862450 mask 0xffff00 : parse_ndn;
	default : ingress;
    }

}

parser parse_ndn_lp {
    return select(current(8,8)) {
	ENCODING_2BYTE : parse_medium_ndnlp;
	default : parse_small_ndnlp;
    }
}

header block_112b_t small_ndnlp;
header block_144b_t medium_ndnlp;

parser parse_small_ndnlp {
    extract(small_ndnlp);
    return parse_ndn;
}

parser parse_medium_ndnlp {
    extract(medium_ndnlp);
    return parse_ndn;
}

parser parse_ndn {
    return select(current(8,8)) {
	ENCODING_2BYTE : parse_medium_tlv0;
	ENCODING_4BYTE : parse_big_tlv0;
	ENCODING_8BYTE : parse_huge_tlv0;
	default : parse_small_tlv0;
    }
}

header smallTL_t small_tlv0;
header mediumTL_t medium_tlv0;
header bigTL_t big_tlv0;
header hugeTL_t huge_tlv0;

parser parse_small_tlv0 {
    extract(small_tlv0);
    set_metadata(flow_metadata.packetType, small_tlv0.tl_code);
    return parse_v0;
}
parser parse_medium_tlv0 {
    extract(medium_tlv0);
    set_metadata(flow_metadata.packetType, medium_tlv0.tl_code);
    return parse_v0;
}
parser parse_big_tlv0 {
    extract(big_tlv0);
    return parse_v0;
}
parser parse_huge_tlv0 {
    extract(huge_tlv0);
    return parse_v0;
}

// Checking the next type, even if a name is the only TLV-type that can follow the TLV0
parser parse_tlv0 {
    return select(current(0,8)) {
	NDNTYPE_NAM : size_name;
	default : parse_error p4_pe_default;
    }
}

parser size_name {
    return select(current(8,8)) {
	ENCODING_2BYTE : parse_medium_name;
	ENCODING_4BYTE : parse_big_name;
	ENCODING_8BYTE : parse_huge_name;
	default : parse_small_name;
    }
}

header smallTL_t small_name;
header mediumTL_t medium_name;
header bigTL_t big_name;
header hugeTL_t huge_name;

// the current impl. assumes that name components cannot have a lenght encoding greater than 1B.
// however, it includes as comments an untested mechanism to deal with variable encoding of 
// this field. Be aware that such a mechanim would also require changes to the corresponding metadata definitions to work.

parser parse_small_name {
    set_metadata(name_metadata.name_size, current(8,8));
    extract(small_name);
    //set_metadata(name_metadata.name_size, small_name.tl_length);
    //set_metadata(name_metadata.name_mask, 0x00ff);
    return parse_name;
}
parser parse_medium_name {
    extract(medium_name);
    //set_metadata(name_metadata.name_size, medium_name.tl_length);
    //set_metadata(name_metadata.name_mask, 0xffff);
    return parse_name;
}
parser parse_big_name {
    extract(big_name);
    //set_metadata(name_metadata.name_size, big_name.tl_length);
    return parse_name;
}
parser parse_huge_name {
    extract(huge_name);
    //set_metadata(name_metadata.name_size, huge_name.tl_length);
    return parse_name;
}

parser parse_name {
    return select(current(0,8)) {
	NDNTYPE_COM : parse_components; 
        NDNTYPE_IS2 : parse_isha256;
	default : parse_error p4_pe_default;
    }
}


header fixedTLV_t components[MAX_NAME_COMPONENTS];

parser parse_components {
    set_metadata(name_metadata.comp_len, current(8,8) );
    extract(components[next]);
    set_metadata(name_metadata.name_size, name_metadata.name_size - name_metadata.comp_len - 2); // the last '2' subtracts the T and L for this TLV block
    //set_metadata(name_metadata.name_size, (name_metadata.name_size & name_metadata.name_mask) - name_metadata.comp_len);
//set_metadata(name_metadata.name_size, (name_metadata.name_size & name_metadata.name_mask) - components[last].tlv_length);
    // beware: we're omitting to check isha256
    return select(name_metadata.name_size) {
	0 : parse_afterName;
	default : parse_components;                     
    }
}

header fixedTLV_t isha256;

parser parse_isha256{
    extract(isha256);
    return select(current(0,8)){
        NDNTYPE_NON : parse_nonce;
        NDNTYPE_MTI : parse_metainfo;
	default : parse_error p4_pe_default;
    }
}
parser parse_afterName {
return select(current(0,8)) {
        NDNTYPE_IS2 : parse_isha256;
	NDNTYPE_NON : parse_nonce;
        NDNTYPE_MTI : parse_metainfo;
	default : parse_error p4_pe_default;
    }
}

header fixedTLV_t nonce;

parser parse_nonce{
    extract(nonce);
    return select(current(0,8)) {
        NDNTYPE_LIF : parse_lifetime;
	default : ingress;
    }
}

header fixedTLV_t lifetime;

parser parse_lifetime{
    extract(lifetime);
    return ingress;
}

header fixedTLV_t metainfo;

parser parse_metainfo{
    extract(metainfo);
    return select(current(0,8)) {
	NDNTYPE_CON : size_content;
	default : parse_error p4_pe_default;
    }
}

parser size_content {
    return select(current(8,8)) {
	ENCODING_2BYTE : parse_medium_content;
	ENCODING_4BYTE : parse_big_content;
	ENCODING_8BYTE : parse_huge_content;
	default : parse_small_content;
    }
}

header smallTL_t small_content;
header mediumTL_t medium_content;
header bigTL_t big_content;
header hugeTL_t huge_content;

parser parse_small_content {
    extract(small_content);
    //set_metadata(name_metadata.name_size, small_content.tl_length);
    return parse_content;
}
parser parse_medium_content {
    extract(medium_content);
    //set_metadata(name_metadata.name_size, medium_content.tl_length);
    return parse_content;
}
parser parse_big_content {
    extract(big_content);
    //set_metadata(name_metadata.name_size, big_content.tl_length);
    return parse_content;
}
parser parse_huge_content {
    extract(huge_content);
    //set_metadata(name_metadata.name_size, huge_content.tl_length);
    return parse_content;
}

parser parse_content{
    //jump(name_metadata.name_size); // construct not implemented yet by the lang.
    return select(current(0,8)) {
	NDNTYPE_SIG : parse_signature_info;
	default : parse_error p4_pe_default;
    }
}

header fixedTLV_t signature_info;

parser parse_signature_info{
    extract(signature_info);
    return select(current(0,8)) {
	NDNTYPE_SGV : parse_signature_value;
	default : parse_error p4_pe_default;
    }
}


header fixedTLV_t signature_value;

parser parse_signature_value{
    extract(signature_value);
    return ingress;
}

// TODO: move the exceptions definition into a separate file
parser_exception p4_pe_default {
    // TODO: increment a counter to keep trace of the dropped packets
    parser_drop;
}
