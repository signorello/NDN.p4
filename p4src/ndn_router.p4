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
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/actions.p4"


field_list name_components1 {
    components[0].tlv_value;
}

field_list name_components2 {
  components[0].tlv_value;
  components[1].tlv_value;
}

field_list name_components3 {
  components[0].tlv_value;
  components[1].tlv_value;
  components[2].tlv_value;
}

field_list name_components4 {
  components[0].tlv_value;
  components[1].tlv_value;
  components[2].tlv_value;
  components[3].tlv_value;
}

field_list name_components_f {
  components[0].tlv_value;
  components[1].tlv_value;
  components[2].tlv_value;
  components[3].tlv_value;
  components[4].tlv_value;
}

field_list_calculation name_hash {
    input {
        name_components_f;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation chash1 {
    input {
        name_components1;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation chash2 {
    input {
        name_components2;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation chash3 {
    input {
        name_components3;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation chash4 {
    input {
        name_components4;
    }
    algorithm : crc16;
    output_width : 16;
}

// table to count the name components
table count_table {
  reads {
    components[0] : valid;
    components[1] : valid;
    components[2] : valid;
    components[3] : valid;
    components[4] : valid;
  }
  actions {
    storeNumOfComponents;
    _drop;
  }
  size : MAX_NAME_COMPONENTS;
}

table hashName_table{
  actions{
    computeStoreTablesIndex;
  }
  size : 1;
}

// Pending Interest Table
table pit_table {
    reads {
	flow_metadata.packetType : exact;
    }
    actions {
        readPitEntry; 	
        cleanPitEntry; 	
    }
    size : 2;
}

table updatePit_table {
    reads {
	flow_metadata.hasFIBentry : exact;
    }
    actions { 
	updatePit_entry;
	_drop;
    }
    size : 2;
}

table routeData_table {
    reads {
	flow_metadata.isInPIT : exact;
    }
    actions {
	setOutputIface;
	_drop;
    }
    size : 20; // this value depends on the number of the available ifaces
}

// Forwarding Information Base
table fib_table {
    reads {
	name_metadata.components : exact;
        comp_metadata.c1 : ternary;
	comp_metadata.c2 : ternary;
    	comp_metadata.c3 : ternary;
    	comp_metadata.c4 : ternary;
    	name_metadata.name_hash : ternary;
    }
    actions {
        set_egr;
	_drop;
    }
}

// by now there is no cache
control ingress {
    apply(count_table);
    if (name_metadata.components != 0) {
	  apply(hashName_table);
    	  apply(pit_table);

    	  if( flow_metadata.packetType == NDNTYPE_INT )
    	  { 
    	     if(flow_metadata.isInPIT == 0){ 
    	        apply(fib_table);
    	     }
    	    
    	     // the next call either updates or adds an entry
    	     apply(updatePit_table);
    	  }
    	  else {           // this is a Data packet
	      // if unsolicited : drop it
	      // else : retrieve PIT entry and send downstream
	      apply(routeData_table);
    	  }
    }
}

table send_packet_table {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_macs;
        _drop;
    }
    size: 256;
}

control egress {
    // may be a future place for caching logic
    //apply(send_packet_table);
}
