//`include "../struct_s.sv"
//`include "./src/full_matcher_types.sv"

interface full_matcher_if ();

  import full_matcher_types::*;

  logic [MAX_PACKET_SIZE-1:0] data;
  rule_id_t rule_id;
  logic last; // last rule
  logic valid;

  logic [MAX_PACKET_SIZE-1:0] data_resp;
  rule_id_t rule_id_resp;
  logic last_resp; // last rule
  logic valid_resp;
  logic match;

  // rule_id_t rule_id_resp;
  // data_id_t data_id_resp;
  // logic match;
  // logic valid_resp;
  
  logic full;


  modport fm ( // full matcher
    input data, rule_id, valid, last,
    output data_resp, rule_id_resp, valid_resp, last_resp, match
    //output rule_id_resp, data_id_resp, match, valid_resp, full

  );

  modport hs ( // hash function
    output data, rule_id, valid, last
  );

  // no modport for stage crossing, will have 2 fif instances
  // modport fm (
  //   input data, rule_id, valid,
  //   output match
  // );

  modport axi_rx (
    output data, rule_id, valid, last
  );

  modport axi_tx (
    input data_resp, rule_id_resp, valid_resp, last_resp
  );

endinterface