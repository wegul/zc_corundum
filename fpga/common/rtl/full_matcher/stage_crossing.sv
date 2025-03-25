import full_matcher_types::*;

module stage_crossing
(
  input logic h_clk, f_clk, n_rst,
  full_matcher_if.fm h_fif, // connects to stage 1
  full_matcher_if.hs f_fif // connects to stage 2
);

  // need a buffer stage 1 -> stage 2
  // . buffer should be in h_clk domain so that it can fill efficiently
  // . output of the buffer is accessed in the f_clk domain
  // . do not need a large buffer going the other way because we are increasing freq (did it anyways for generality)

  localparam BUFF_LEN = 8;


  // **************************************
  //
  // STG1 -> STG2 BUFFER
  //
  // **************************************
  queue_entry_t [BUFF_LEN-1:0] msg, msg_next; // entries
  logic [$clog2(BUFF_LEN)-1:0] head, head_next, tail, tail_next; // pointers
  logic [$clog2(MAX_GROUPS)-1:0] group_pointer, group_pointer_next; // group pointer for fm
  logic [BUFF_LEN-1:0] inv_msg, inv_msg_next; // f_clk domain pulls high in the cycle AFTER the head is pushed to fm
                                              // gets pulled low once f_clk domain sees the entry is invalid
                                              // this is where instability happens but the handshake should succeed
  logic [BUFF_LEN-1:0] access, access_next; // works like inv except it makes sure that the entry is on the output for a full cycle of f_clk,
                                            // goes to 1 when valid is high on rising edge of f_clk
                                            // goes to 0 when head is on the element and rising edge of f_clk
  
  always_ff @ (posedge h_clk, negedge n_rst)
  begin: STG1_2_H_CR
    if (~n_rst)
    begin
      for (int i = 0; i < BUFF_LEN; i++)
        msg[i] <= '0;
      tail <= '0;
    end
    else
    begin
      for (int i = 0; i < BUFF_LEN; i++)
        msg[i] <= msg_next[i];
      tail <= tail_next;
    end
  end

  always_comb
  begin: STG1_2_H
    for (int i = 0; i < BUFF_LEN; i++)
      msg_next[i] = msg[i];
    tail_next = tail;

    for (int i = 0; i < BUFF_LEN; i++)
    begin
      if (i == tail && h_fif.valid) // place new data
      begin
        msg_next[i].data = h_fif.data;
        msg_next[i].groups[msg[i].num_groups] = h_fif.rule_id;
        //msg_next[i].data_id = h_fif.data_id;
        msg_next[i].num_groups = msg[i].num_groups + 'd1;
        if (h_fif.last)
        begin
          tail_next = tail == BUFF_LEN-1 ? '0 : tail + 'd1;
          msg_next[i].valid = 1'b1;
          msg_next[i].num_groups = msg[i].num_groups;
        end
      end
      if (inv_msg[i])
      begin
        msg_next[i].valid = 1'b0;
        msg_next[i].num_groups = '0;
      end
    end
  end

  always_ff @ (posedge f_clk, negedge n_rst)
  begin: STG1_2_F_CR
    if (~n_rst)
    begin
      head <= '0;
      inv_msg <= '0;
      access <= '0;
      group_pointer <= '0;
    end
    else
    begin
      head <= head_next;
      inv_msg <= inv_msg_next;
      access <= access_next;
      group_pointer <= group_pointer_next;
    end
  end

  always_comb
  begin: STG1_2_F
    head_next = head;
    inv_msg_next = inv_msg;
    access_next = access;
    f_fif.data = '0;
    f_fif.rule_id = NO_RULE;
    f_fif.last = 1'b0;
    f_fif.valid = '0;
    group_pointer_next = group_pointer;

    if (access[head])
    begin
      f_fif.data = msg[head].data;
      f_fif.rule_id = msg[head].groups[group_pointer];
      f_fif.valid = 1'b1;
      group_pointer_next = group_pointer + 'd1;
      if (group_pointer == msg[head].num_groups)
      begin
        head_next = head == BUFF_LEN-1 ? '0 : head + 'd1;
        inv_msg_next[head] = 1'b1;
        access_next[head] = 1'b0;
        group_pointer_next = '0;
        f_fif.last = 1'b1;
      end
    end

    for (int i = 0; i < BUFF_LEN; i++)
    begin
      if (inv_msg[i] && ~msg[i].valid) // clear invalidate signal to complete handshake
      begin
        inv_msg_next[i] = 1'b0;
      end
      if (msg[i].valid && ~access[i] && ~inv_msg[i]) // might have problems with queue overflow, make sure buffer is sufficiently large
        access_next[i] = 1'b1;
    end
  end



  // **************************************
  //
  // STG2 -> STG1 BUFFER
  //
  // **************************************
  // stg2_msg_t [BUFF_LEN-1:0] resp, resp_next;
  // logic [$clog2(BUFF_LEN)-1:0] head_resp, head_resp_next, tail_resp, tail_resp_next; // pointers
  // logic [BUFF_LEN-1:0] inv_msg_resp, inv_msg_resp_next; // h_clk domain pulls high in the cycle AFTER the head is pushed to fm
  //                                             // gets pulled low once h_clk domain sees the entry is invalid
  //                                             // this is where instability happens but the handshake should succeed
  // logic [BUFF_LEN-1:0] access_resp, access_resp_next;
  
  // always_ff @ (posedge f_clk, negedge n_rst)
  // begin: STG2_1_F_CR
  //   if (~n_rst)
  //   begin
  //     for (int i = 0; i < BUFF_LEN; i++)
  //       resp[i] <= '0;
  //     tail_resp <= '0;
  //   end
  //   else
  //   begin
  //     for (int i = 0; i < BUFF_LEN; i++)
  //       resp[i] <= resp_next[i];
  //     tail_resp <= tail_resp_next;
  //   end
  // end

  // always_comb
  // begin: STG2_1_F
  //   for (int i = 0; i < BUFF_LEN; i++)
  //     resp_next[i] = resp[i];
  //   tail_resp_next = tail_resp;

  //   for (int i = 0; i < BUFF_LEN; i++)
  //   begin
  //     if (i == tail_resp && f_fif.valid_resp) // place new data
  //     begin
  //       resp_next[i].match = f_fif.match;
  //       resp_next[i].rule_id_resp = f_fif.rule_id_resp;
  //       resp_next[i].data_id_resp = f_fif.data_id_resp;
  //       resp_next[i].valid = 1'b1;
  //       tail_resp_next = tail_resp == BUFF_LEN-1 ? '0 : tail_resp + 'd1;
  //     end
  //     if (inv_msg_resp[i])
  //       resp_next[i].valid = 1'b0;
  //   end
  // end

  // always_ff @ (posedge h_clk, negedge n_rst)
  // begin: STG2_1_H_CR
  //   if (~n_rst)
  //   begin
  //     head_resp <= '0;
  //     inv_msg_resp <= '0;
  //     access_resp <= '0;
  //   end
  //   else
  //   begin
  //     head_resp <= head_resp_next;
  //     inv_msg_resp <= inv_msg_resp_next;
  //     access_resp <= access_resp_next;
  //   end
  // end

  // always_comb
  // begin: STG2_1_H
  //   head_resp_next = head_resp;
  //   inv_msg_resp_next = inv_msg_resp;
  //   access_resp_next = access_resp;
  //   h_fif.match = '0;
  //   h_fif.rule_id = NO_RULE;
  //   h_fif.data_id = '0;
  //   h_fif.valid_resp = '0;

  //   if (access_resp[head_resp])
  //   begin
  //     head_resp_next = head_resp == BUFF_LEN-1 ? '0 : head_resp + 'd1;
  //     inv_msg_resp_next[head_resp] = 1'b1;
  //     access_resp_next[head_resp] = 1'b0;
  //     h_fif.match = resp[head_resp].match;
  //     h_fif.rule_id_resp = resp[head_resp].rule_id_resp;
  //     h_fif.data_id_resp = resp[head_resp].data_id_resp;
  //     h_fif.valid_resp = 1'b1;
  //   end

  //   for (int i = 0; i < BUFF_LEN; i++)
  //   begin
  //     if (inv_msg_resp[i] && ~resp[i].valid) // clear invalidate signal to complete handshake
  //     begin
  //       inv_msg_resp_next[i] = 1'b0;
  //     end
  //     if (resp[i].valid && ~access_resp[i] && ~inv_msg_resp[i]) // might have problems with queue overflow, make sure buffer is sufficiently large
  //       access_resp_next[i] = 1'b1;
  //   end
  // end

endmodule