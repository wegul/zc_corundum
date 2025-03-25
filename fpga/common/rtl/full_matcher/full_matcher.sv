//`include "./full_matcher_if.sv"
////include "./crossbar_if.sv"
//`define SMALL_IMPL // Use to decrease I/O when implementing

import full_matcher_types::*;

module full_matcher
(
  input logic clk,
  input logic n_rst,
  `ifdef SMALL_IMPL
  input logic [31:0] data,
  input logic [RID_WIDTH-1:0] rule_id,
  input logic valid,
  output logic match
  `else
  full_matcher_if.fm fif
  `endif
);

  nfa_if nif ();
  `ifdef SMALL_IMPL
  full_matcher_if fif ();
  assign fif.data = {(1500*8)*{data[0]}};
  assign fif.rule_id = rule_id_t'(rule_id);
  assign fif.valid = valid;
  assign match = |nif.match;
  `endif

  `define USE_MULTI_QUEUE
  `ifdef USE_MULTI_QUEUE
  multi_packet_nfa_queue queue(
    clk,
    n_rst,
    fif,
    nif
  );
  `else
  packet_nfa_queue queue(
    clk,
    n_rst,
    fif,
    nif
  );
  `endif

  nfa_table atm_tbl(
    clk,
    n_rst,
    nif
  );

endmodule