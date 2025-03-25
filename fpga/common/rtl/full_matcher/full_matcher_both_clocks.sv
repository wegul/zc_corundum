
import full_matcher_types::*;

module full_matcher_both_clocks
(
  input logic stg1_clk, stg2_clk,
  input logic n_rst,
  full_matcher_if.fm fif
);

  full_matcher_if hidden_fif ();

  stage_crossing sc (.h_clk(stg1_clk), .f_clk(stg2_clk), .n_rst(n_rst),
                     .h_fif(fif), .f_fif(hidden_fif));

  full_matcher fm (.clk(f_clk), .n_rst(n_rst), .fif(hidden_fif));

  assign fif.rule_id_resp = hidden_fif.rule_id_resp;
  assign fif.data_id_resp = hidden_fif.data_id_resp;
  assign fif.match = hidden_fif.match;
  assign fif.valid_resp = hidden_fif.valid_resp;
  assign fif.full = hidden_fif.full;

endmodule