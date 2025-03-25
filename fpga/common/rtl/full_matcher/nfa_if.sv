//`include "../struct_s.sv"
`include "./full_matcher_types.sv"

interface nfa_if ();

  import full_matcher_types::*;

  logic [N_CB_CHN-1:0] request;
  logic [N_CB_CHN-1:0] ready;
  rule_id_t [N_CB_CHN-1:0] id;
  symbol_t [N_CB_CHN-1:0] symbol;
  logic [N_CB_CHN-1:0] match;
  logic [N_CB_CHN-1:0] clear;

  modport arb (
    input ready,
    input match,

    output request,
    output clear,
    output id,
    output symbol
  );

  modport nfa (
    output ready,
    output match,

    input request,
    input clear,
    input id,
    input symbol
  );

endinterface