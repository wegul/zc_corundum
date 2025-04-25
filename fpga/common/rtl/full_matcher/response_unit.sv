import full_matcher_types::*;

module response_unit
(
  input logic clk, n_rst,
  output logic [MAX_PACKET_SIZE-1:0] data_resp,
  output logic [RID_WIDTH-1:0] rule_id_resp,
  output logic valid_resp, last_resp, match,
  input resp_entry_t [N_CB_CHN-1:0] response
);

  // the channel pointer will cycle through all channels,
  // stopping when it finds a valid entry and processes it
  logic [$clog2(N_CB_CHN)-1:0] chn_ptr, chn_ptr_next;
  resp_entry_t [N_CB_CHN-1:0] entry, entry_next;

  always_ff @ (posedge clk, negedge n_rst)
  begin
    if (~n_rst)
    begin
      chn_ptr <= '0;
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        entry[i] <= '0; 
      end
    end
    else
    begin
      chn_ptr <= chn_ptr_next;
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        entry[i] <= entry_next[i]; 
      end
    end
  end

  always_comb
  begin
    chn_ptr_next = chn_ptr == N_CB_CHN-1 ? '0 : chn_ptr + 'd1;
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      entry_next[i] = entry[i];
      if (response[i].valid)
        entry_next[i] = response[i];
    end
    if (entry[chn_ptr].valid)
      entry_next[chn_ptr].valid = 1'b0;
  end

  assign data_resp = entry[chn_ptr].data_resp;
  assign rule_id_resp = entry[chn_ptr].rule_id_resp;
  //assign fif.data_id_resp = entry[chn_ptr].data_id_resp;
  assign match = entry[chn_ptr].match;
  assign last_resp = 1'b1;
  assign valid_resp = entry[chn_ptr].valid;

endmodule