import full_matcher_types::*;

module axi_fifo_tx
#(
  parameter DEPTH = 1024,
  parameter DATA_WIDTH = 512,
  parameter KEEP_WIDTH = 64,
  parameter KEEP_ENABLE = 1,
  parameter LAST_ENABLE = 1,
  parameter ID_ENABLE = 0,
  parameter DEST_ENABLE = 0,
  parameter USER_ENABLE = 0,
  parameter RAM_PIPELINE = 2,
  parameter DROP_WHEN_FULL = 1,
  parameter FRAME_FIFO = 1
)
(
  input logic aclk, fclk, rst,

  input logic tready,
  output logic [DATA_WIDTH-1:0] tdata,
  output logic tvalid,
  output logic [KEEP_WIDTH-1:0] tkeep,
  output logic tlast,

  output logic tready_bypass,
  input logic [DATA_WIDTH-1:0] tdata_bypass,
  input logic tvalid_bypass,
  input logic [KEEP_WIDTH-1:0] tkeep_bypass,
  input logic tlast_bypass,

  full_matcher_if.axi_tx fif
);

  //assign tdata = {(DATA_WIDTH-1){fif.match}}; // make this packet data for malicious data
  //assign tvalid = 1'b1;
  //assign tlast = 1'b1;



  localparam BUFF_LEN = 8;

  logic [MAX_PACKET_SIZE/DATA_WIDTH-1:0] [DATA_WIDTH-1:0] data_out;
  logic [$clog2(MAX_PACKET_SIZE/DATA_WIDTH):0] data_pointer, data_pointer_next;
  stg2_msg_t [BUFF_LEN-1:0] resp, resp_next;
  logic [$clog2(BUFF_LEN)-1:0] head_resp, head_resp_next, tail_resp, tail_resp_next; // pointers
  logic [BUFF_LEN-1:0] inv_msg_resp, inv_msg_resp_next; // h_clk domain pulls high in the cycle AFTER the head is pushed to fm
                                              // gets pulled low once h_clk domain sees the entry is invalid
                                              // this is where instability happens but the handshake should succeed
  logic [BUFF_LEN-1:0] access_resp, access_resp_next;

  genvar i;
  generate
    for (i = 0; i < MAX_PACKET_SIZE/DATA_WIDTH; i++)
    if (i == MAX_PACKET_SIZE/DATA_WIDTH - 1)
      assign data_out[i] = {resp[head_resp].groups, resp[head_resp].num_groups};
    else
      assign data_out[i] = resp[head_resp].data[DATA_WIDTH*(i+1)-1:DATA_WIDTH*i];
  endgenerate
  
  always_ff @ (posedge fclk, posedge rst)
  begin: STG2_1_F_CR
    if (rst)
    begin
      for (int i = 0; i < BUFF_LEN; i++)
        resp[i] <= '0;
      tail_resp <= '0;
    end
    else
    begin
      for (int i = 0; i < BUFF_LEN; i++)
        resp[i] <= resp_next[i];
      tail_resp <= tail_resp_next;
    end
  end

  always_comb
  begin: STG2_1_F
    for (int i = 0; i < BUFF_LEN; i++)
      resp_next[i] = resp[i];
    tail_resp_next = tail_resp;

    for (int i = 0; i < BUFF_LEN; i++)
    begin
      if (i == tail_resp && fif.valid_resp) // place new data
      begin
        resp_next[i].data = fif.data_resp;
        resp_next[i].groups[resp[i].num_groups] = fif.rule_id_resp;
        resp_next[i].valid = 1'b1;
        resp_next[i].num_groups = resp[i].num_groups + 'd1;
        if (fif.last_resp)
          tail_resp_next = tail_resp == BUFF_LEN-1 ? '0 : tail_resp + 'd1;
      end
      if (inv_msg_resp[i])
      begin
        resp_next[i].valid = 1'b0;
        resp_next[i].num_groups = '0;
      end
    end
  end

  always_ff @ (posedge aclk, posedge rst)
  begin: STG2_1_H_CR
    if (rst)
    begin
      head_resp <= '0;
      inv_msg_resp <= '0;
      access_resp <= '0;
      data_pointer <= '0;
    end
    else
    begin
      head_resp <= head_resp_next;
      inv_msg_resp <= inv_msg_resp_next;
      access_resp <= access_resp_next;
      data_pointer <= data_pointer_next;
    end
  end

  always_comb
  begin: STG2_1_H
    head_resp_next = head_resp;
    inv_msg_resp_next = inv_msg_resp;
    access_resp_next = access_resp;

    data_pointer_next = data_pointer;
    tdata = '0;
    tvalid = '0;
    tkeep = '0;
    tlast = '0;

    tready_bypass = 1'b0;

    if (data_pointer == '0 && tvalid_bypass) // can't be in middle of a transmission
    begin
      tready_bypass = tready;
      tdata = tdata_bypass;
      tvalid = tvalid_bypass;
      tkeep = tkeep_bypass;
      tlast = tlast_bypass;
    end
    else
    begin
      if (access_resp[head_resp] && tready)
      begin
        data_pointer_next = data_pointer + 'd1;

        tvalid = 1'b1;
        tkeep = '1;
        tdata = data_out[data_pointer];

        if (data_pointer == MAX_PACKET_SIZE/DATA_WIDTH - 1) // move head when done
        begin
          tlast = 1'b1;
          data_pointer_next = '0;
          head_resp_next = head_resp == BUFF_LEN-1 ? '0 : head_resp + 'd1;
          inv_msg_resp_next[head_resp] = 1'b1;
          access_resp_next[head_resp] = 1'b0;
        end
      end
    end

    for (int i = 0; i < BUFF_LEN; i++)
    begin
      if (inv_msg_resp[i] && ~resp[i].valid) // clear invalidate signal to complete handshake
      begin
        inv_msg_resp_next[i] = 1'b0;
      end
      if (resp[i].valid && ~access_resp[i] && ~inv_msg_resp[i]) // might have problems with queue overflow, make sure buffer is sufficiently large
        access_resp_next[i] = 1'b1;
    end
  end

endmodule