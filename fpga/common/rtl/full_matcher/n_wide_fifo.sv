`include "./n_wide_fifo_if.sv"

import full_matcher_types::*;

module n_wide_fifo
(
  input logic clk, n_rst,
  n_wide_fifo_if.fifo fif
);

  import full_matcher_types::*;

  queue_entry_t [fif.N_FIFO_ENTRY_LOCAL-1:0] entry, entry_next;
  logic [$clog2(fif.N_FIFO_ENTRY_LOCAL):0] head_next, tail_next;
  logic [$clog2(fif.N_FIFO_ENTRY_LOCAL):0] capacity_next;

  always_ff @ (posedge clk, negedge n_rst)
  begin
    if (~n_rst)
    begin
      for (int i = 0; i < fif.N_FIFO_ENTRY_LOCAL; i++)
      begin
        entry[i].valid <= '0;
        for (int j = 0; j < MAX_GROUPS; j++)
          entry[i].groups[j] <= '0;
        entry[i].num_groups <= '0;
        entry[i].group_pointer <= '0;
        entry[i].data_id <= '0;
        entry[i].data <= '0;
      end
      // fif.head <= '0;
      fif.tail <= '0;
      fif.capacity <= fif.N_FIFO_ENTRY_LOCAL;
    end
    else
    begin
      for (int i = 0; i < fif.N_FIFO_ENTRY_LOCAL; i++)
      begin
        entry[i].valid <= entry_next[i].valid;
        for (int j = 0; j < MAX_GROUPS; j++)
          entry[i].groups[j] <= entry_next[i].groups[j];
        entry[i].num_groups <= entry_next[i].num_groups;
        entry[i].group_pointer <= entry_next[i].group_pointer;
        entry[i].data_id <= entry_next[i].data_id;
        entry[i].data <= entry_next[i].data;
      end
      // fif.head <= head_next;
      fif.tail <= tail_next;
      fif.capacity <= capacity_next;
    end
  end

  always_comb
  begin: NEXT_ENTRY_LOGIC
    for (int i = 0; i < fif.N_FIFO_ENTRY_LOCAL; i++)
    begin
      entry_next[i].valid = entry[i].valid;
      for (int j = 0; j < MAX_GROUPS; j++)
        entry_next[i].groups[j] = entry[i].groups[j];
      entry_next[i].num_groups = entry[i].num_groups;
      entry_next[i].group_pointer = entry[i].group_pointer;
      entry_next[i].data_id = entry[i].data_id;
      entry_next[i].data = entry[i].data;
      if (fif.wen)
      begin
        entry_next[fif.tail].valid = 1'b1;
        entry_next[fif.tail].groups[entry[fif.tail].num_groups] = fif.rule_id;
        entry_next[fif.tail].num_groups = entry[fif.tail].num_groups + 'd1;
        entry_next[fif.tail].data_id = fif.data_id;
        entry_next[fif.tail].data = fif.wdata;
      end
      if (fif.raddr == i && fif.done)
        entry_next[i].group_pointer = entry[i].group_pointer + 'd1;
      if (fif.raddr == i && fif.inv_entry)
      begin
        entry_next[i].valid = 1'b0;
        entry_next[i].num_groups = '0;
        entry_next[i].group_pointer = '0;
      end
    end
  end

  always_comb
  begin: NEXT_HEAD_TAIL_LOGIC
    // head_next = fif.head;
    tail_next = fif.tail;

    // if (fif.head != fif.tail && fif.raddr == fif.head && fif.inv_entry)
    //   if (fif.head != fif.N_FIFO_ENTRY_LOCAL-1)
    //     head_next = fif.head + 'd1;
    //   else
    //     head_next = '0;
    // else if (~entry[fif.head].valid && fif.head != fif.tail)
    //   head_next = fif.head + 'd1;

    // if (fif.wen && fif.last) // nothing to stop this from overwriting something
    //   if (fif.tail == fif.N_FIFO_ENTRY_LOCAL-1)
    //     tail_next = '0;
    //   else
    //     tail_next = fif.tail + 'd1;
    if (fif.wen && fif.last) // latch when writing but not last
    begin
      tail_next = fif.N_FIFO_ENTRY_LOCAL-1;
      for (int i = fif.N_FIFO_ENTRY_LOCAL-1; i > 0; i--)
        if (~entry[i].valid && fif.tail != i)
          tail_next = i;
    end
    else if (~fif.wen) // important when the queue is full
    begin
      tail_next = fif.N_FIFO_ENTRY_LOCAL-1;
      for (int i = fif.N_FIFO_ENTRY_LOCAL-1; i > 0; i--)
        if (~entry[i].valid)
          tail_next = i;
    end
  end

  always_comb
  begin: OUTPUT_ENTRY_LOGIC
    fif.valid_out = entry[fif.raddr].valid;
    fif.cur_groups = entry[fif.raddr].num_groups - entry[fif.raddr].group_pointer;
    fif.rule_id_out = entry[fif.raddr].groups[entry[fif.raddr].group_pointer];
    fif.data_id_out = entry[fif.raddr].data_id;
    fif.data_out = entry[fif.raddr].data;
  end

  always_comb
  begin: CAPACITY_LOGIC
    capacity_next = fif.capacity;
    if (fif.last && entry_next[fif.raddr].valid && fif.inv_entry && fif.capacity != '0) // operations cancel out
      capacity_next = fif.capacity;
    else if (fif.last && fif.capacity != '0)
      capacity_next = fif.capacity - 'd1;
    // if (head_next != fif.head)
    else if (entry[fif.raddr].valid && fif.inv_entry)
      capacity_next = fif.capacity + 'd1;
  end

endmodule