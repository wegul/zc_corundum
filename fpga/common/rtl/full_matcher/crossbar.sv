//`include "../struct_s.sv"
//`include "./src/full_matcher_types.sv"
////include "./crossbar_if.sv"

module crossbar
(
  input logic clk,
  input logic n_rst,

  crossbar_if.cb cif
);

  import full_matcher_types::*;

  // Latch request signals on the NFA side where the multiplexing logic is
  rule_id_t [N_CB_CHN-1:0] index_next;
  symbol_t [N_CB_CHN-1:0] out_symbol_next;

  // Also latch cif.nfa_status to make a state machine
  nfa_status_t [N_CB_CHN-1:0] nfa_status_next;

  always_ff @ (posedge clk, negedge n_rst)
  begin
    if (~n_rst)
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        cif.index[i]      <= NO_RULE;
        cif.out_symbol[i] <= NULL_SYMBOL;

        cif.nfa_status[i] <= IDLE;
      end
    else
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        cif.index[i]      <= index_next[i];
        cif.out_symbol[i] <= out_symbol_next[i];

        cif.nfa_status[i] <= nfa_status_next[i];
      end
  end

  always_comb
  begin
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      index_next[i] = NO_RULE;
      out_symbol_next[i] = '0;
      cif.busy[i] = 1'b0;
      cif.n_clear[i] = 1'b1;

      case (cif.nfa_status[i])
        IDLE: begin
          index_next[i] = cif.rule_req[i] ? cif.rule_id[i] : NO_RULE;
          out_symbol_next[i] = cif.rule_req[i] ? cif.in_symbol[i] : NULL_SYMBOL;
          cif.busy[i] = 1'b0;
          cif.n_clear[i] = 1'b1;
        end
        PROC: begin
          index_next[i] = cif.index[i];
          out_symbol_next[i] = cif.rule_req[i] ? cif.in_symbol[i] : NULL_SYMBOL;
          cif.busy[i] = 1'b0;
          cif.n_clear[i] = 1'b1;
        end
        FWD: begin
          index_next[i] = NO_RULE;
          out_symbol_next[i] = NULL_SYMBOL;
          cif.busy[i] = 1'b0;
          cif.n_clear[i] = 1'b0;
        end
        DROP: begin
          index_next[i] = NO_RULE;
          out_symbol_next[i] = NULL_SYMBOL;
          cif.busy[i] = 1'b0;
          cif.n_clear[i] = 1'b0;
        end
        ERR: begin
          index_next[i] = NO_RULE;
          out_symbol_next[i] = NULL_SYMBOL;
          cif.busy[i] = 1'b0;
          cif.n_clear[i] = 1'b0;
        end
      endcase

      for (int j = 0; j < N_CB_CHN; j++)
        if (cif.rule_req[i])
          if ((i != j && cif.rule_id[i][RID_WIDTH-1:1] == cif.index[j][RID_WIDTH-1:1]) || (i > j && cif.rule_id[i][RID_WIDTH-1:1] == cif.rule_id[j][RID_WIDTH-1:1]))
          begin
            index_next[i] = NO_RULE;
            out_symbol_next[i] = NULL_SYMBOL;
            cif.busy[i] = 1'b1;
          end
    end
  end

  always_comb
  begin
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      nfa_status_next[i] = cif.nfa_status[i];

      case (cif.nfa_status[i])
        IDLE: begin
          if (cif.rule_id[i] != NO_RULE && cif.rule_req[i] && ~cif.busy[i] && cif.ready[i])
            nfa_status_next[i] = PROC;
        end
        // PROC state alerts the crossbar input is being processed
        PROC: begin
        // Unexpected rule change -> ERR
        if (cif.rule_id[i] != cif.index[i] || ~cif.rule_req[i])
          nfa_status_next[i] = ERR;
        else if (cif.match[i])
          nfa_status_next[i] = DROP;
        else if (cif.done[i])
          nfa_status_next[i] = FWD;
        end
        FWD: nfa_status_next[i] = IDLE;
        DROP: nfa_status_next[i] = IDLE;
        ERR: nfa_status_next[i] = IDLE;
      endcase
    end
  end

endmodule

// the following website was super useful for includes
// https://electronics.stackexchange.com/questions/76288/verilog-simulation-error-module-was-already-declared
