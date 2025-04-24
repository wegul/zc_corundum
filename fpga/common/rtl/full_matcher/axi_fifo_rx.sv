import full_matcher_types::*;

module axi_fifo_rx
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

  input logic [DATA_WIDTH-1:0] tdata,
  input logic tvalid,
  input logic [KEEP_WIDTH-1:0] tkeep,
  input logic tlast,
  output logic tready,

  output logic [DATA_WIDTH-1:0] tdata_bypass,
  output logic tvalid_bypass,
  output logic [KEEP_WIDTH-1:0] tkeep_bypass,
  output logic tlast_bypass,
  input logic tready_bypass,

  full_matcher_if.axi_rx fif
);

  localparam LG_RID_WIDTH = 16;
  localparam PIPE_LEN = 2;
  localparam BITS_PER_KEEP = DATA_WIDTH/KEEP_WIDTH;
  localparam ETHER_LEN = 14;
  localparam IP_LEN = 20;
  //localparam NUM_RULES_IDX = ETHER_LEN + IP_LEN;
  localparam NUM_RULES_IDX = MAX_PACKET_SIZE/8;
  localparam RULES_IDX = NUM_RULES_IDX + 1;

  logic [$clog2(MAX_PACKET_SIZE/DATA_WIDTH)+1:0] cur_index, cur_index_next;
  // pipe is in fclk and non-pipe is in aclk
  logic [PIPE_LEN-1:0] [MAX_PACKET_SIZE/DATA_WIDTH-1:0] [DATA_WIDTH-1:0] data_acc_pipe;
  logic [MAX_PACKET_SIZE/DATA_WIDTH-1:0] [DATA_WIDTH-1:0] data_acc;
  logic [PIPE_LEN-1:0] [MAX_PACKET_SIZE/DATA_WIDTH-1:0] [KEEP_WIDTH-1:0] keep_acc_pipe;
  logic [MAX_PACKET_SIZE/DATA_WIDTH-1:0] [KEEP_WIDTH-1:0] keep_acc;

  // for strobing in rules
  logic [PIPE_LEN-1:0] [MAX_GROUPS-1:0] [LG_RID_WIDTH-1:0] rule_acc_pipe;
  logic [MAX_GROUPS-1:0] [LG_RID_WIDTH-1:0] rule_acc;
  logic [7:0] cur_rule, cur_rule_next;
  logic [7:0] num_rules;

  typedef enum {IDLE, PROC} strobe_state_t;
  strobe_state_t state, state_next;
  logic strobe_done;
  logic [15:0] strobe_count;

  // bypass logic
  logic [MAX_PACKET_SIZE/DATA_WIDTH:0] [DATA_WIDTH-1:0] bypass_data;
  logic [MAX_PACKET_SIZE/DATA_WIDTH:0] [KEEP_WIDTH-1:0] bypass_keep;
  logic bypass, bypass_next;
  logic [$clog2(MAX_PACKET_SIZE/DATA_WIDTH)+1:0] bypass_index, bypass_index_next;
  logic reset_latch, reset_latch_next; // simulator made me do this - tlast starts out as "x" and it screws with bypass signal

  // collect data -> see if it's long enough -> if bypass, cycle through and transmit
  always_ff @ (posedge aclk, posedge rst)
  begin
    if (rst)
    begin
      bypass_data <= '0;
      bypass_keep <= '0;
      bypass_index <= '0;
      bypass <= '0;
      reset_latch <= 1'b1;
    end
    else
    begin
      if (tvalid && tready)
      begin
        bypass_data[cur_index] <= tdata;
        bypass_keep[cur_index] <= tkeep;
      end
      if (bypass)
      begin
        bypass_data[bypass_index] <= tready_bypass ? '0 : bypass_data[bypass_index];
        bypass_keep[bypass_index] <= tready_bypass ? '0 : bypass_keep[bypass_index];
      end
      if (bypass)
      begin
        if (bypass_index == MAX_PACKET_SIZE/DATA_WIDTH || bypass_index == cur_index)
          bypass_index <= bypass_index;
        else
          if (tready_bypass)
            bypass_index <= bypass_index + 'd1;
      end
      else
        bypass_index <= '0;
      if (bypass && bypass_index == cur_index - 'd1)
        bypass_index <= '0;
      bypass <= bypass_next;
      reset_latch <= (reset_latch && ~tvalid); //|| ~tready; // goes low and then never goes back to high
    end
  end

  assign bypass_next = /*reset_latch ? 1'b0 :*/ bypass ? bypass_index != cur_index - 'd1 : tvalid && ((~(cur_index == MAX_PACKET_SIZE/DATA_WIDTH && tkeep[KEEP_WIDTH-1] == 1'b1) && tlast) || (tlast && cur_index < MAX_PACKET_SIZE/DATA_WIDTH));

  assign tdata_bypass = bypass_data[bypass_index];
  assign tvalid_bypass = bypass;
  assign tkeep_bypass = bypass_keep[bypass_index];
  assign tlast_bypass = bypass_index == cur_index - 'd1;

  // INPUT ACCUMULATOR (axi clk domain)
  always_comb
  begin
    cur_index_next = cur_index;
    if (tvalid && tready)
    begin
      // cur_index update
      if (cur_index == MAX_PACKET_SIZE/DATA_WIDTH)
      begin
        cur_index_next = '0;
      end
      else
        cur_index_next = cur_index + 'd1;
    end
    
    if (bypass && bypass_index == cur_index - 'd1)
      cur_index_next = '0;
  end

  always_ff @ (posedge aclk, posedge rst)
  begin: INPUT_LATCHING
    if (rst)
    begin
      cur_index <= '0;
      for (int j = 0; j < MAX_PACKET_SIZE/DATA_WIDTH; j++)
      begin
        data_acc[j] <= '0;
      end
      num_rules <= '0;
      rule_acc <= '0;
    end
    else
    begin
      cur_index <= cur_index_next;
      if (tvalid)
      begin
        // rule and data update
        if (cur_index == MAX_PACKET_SIZE/DATA_WIDTH)
        begin
          num_rules <= tdata[0+:8] == '0 ? 'd1 : tdata[0+:8];
          rule_acc <= tdata[DATA_WIDTH-1:8];
        end
        else
        begin
          data_acc[cur_index] <= tdata;
          keep_acc[cur_index] <= tkeep;
        end
      end
      if (bypass)
      begin
        for (int j = 0; j < MAX_PACKET_SIZE/DATA_WIDTH; j++)
        begin
          data_acc[j] <= '0;
        end
        num_rules <= '0;
        rule_acc <= '0;
      end
    end
  end


  // STROBE STATE (axi clk domain)
  always_comb
  begin
    state_next = state;
    case (state)
      IDLE:
      begin
        if ((cur_index == MAX_PACKET_SIZE/DATA_WIDTH && cur_index_next == '0) || (tlast && tvalid))
          if (~bypass_next) // inverse bypass condition - don't go into PROC if not met
            state_next = PROC;
      end
      PROC:
      begin
        if (strobe_done && cur_rule == num_rules - 'd1)
          state_next = IDLE;
      end
    endcase
  end

  always_ff @ (posedge aclk, posedge rst)
  begin
    if (rst)
    begin
      state <= IDLE;
    end
    else
      state <= state_next;
  end


  // STROBE DONE (full matcher clk domain)
  always_ff @ (posedge fclk, posedge rst)
  begin
    if (rst)
    begin
      strobe_done <= 1'b0;
      strobe_count <= '0;
    end
    else
    begin
      if (state == PROC)
      begin
        if (strobe_count >= PIPE_LEN)
        begin
          strobe_done <= 1'b1;
          if (cur_rule == num_rules - 'd1)
            strobe_count <= '0;
        end
        else
        begin
          strobe_done <= 1'b0;
          strobe_count <= strobe_count + 'd1;
        end
      end
      else
      begin
        strobe_done <= 1'b0;
        strobe_count <= '0;
      end
    end
  end


  // FIF VALID (full matcher clk domain)
  // always_ff @ (posedge fclk, posedge rst)
  // begin
  //   if (rst)
  //     fif.valid <= 1'b0;
  //   else
  //   begin
  //     if (fif.valid && cur_rule == num_rules - 'd1)
  //       fif.valid <= 1'b0;
  //     if (strobe_done)
  //       fif.valid <= 1'b1;
  //   end
  // end

  assign fif.valid = strobe_done && cur_rule <= num_rules - 'd1 && ~bypass;


  // PIPELINE (full matcher clk domain)
  always_ff @ (posedge fclk, posedge rst)
  begin
    if (rst)
      for (int i = 0; i < PIPE_LEN; i++)
      begin
        rule_acc_pipe[i] <= '0;
        for (int j = 0; j < MAX_PACKET_SIZE/DATA_WIDTH; j++)
        begin
          data_acc_pipe[i][j] <= '0;
          keep_acc_pipe[i][j] <= '0;
        end
      end
    else
      for (int i = 0; i < PIPE_LEN; i++)
      begin
        if (i == 0)
        begin
          rule_acc_pipe[i] <= rule_acc;
          //for (int j = 0; j < MAX_PACKET_SIZE/DATA_WIDTH; j++)
          data_acc_pipe[i] <= data_acc;
          keep_acc_pipe[i] <= keep_acc;
        end
        else
        begin
          rule_acc_pipe[i] <= rule_acc_pipe[i-1];
          for (int j = 0; j < MAX_PACKET_SIZE/DATA_WIDTH; j++)
          begin
            data_acc_pipe[i][j] <= data_acc_pipe[i-1][j];
            keep_acc_pipe[i][j] <= keep_acc_pipe[i-1][j];
          end
        end
      end
  end

  always_ff @ (posedge fclk, posedge rst)
  begin: CUR_RULE
    if (rst)
      cur_rule <= '0;
    else
    begin
      if (strobe_done)
      begin
        if (cur_rule == num_rules - 'd1)
          cur_rule <= '0;
        else
          cur_rule <= cur_rule + 'd1;
      end
    end
  end

  assign tready = state == IDLE && ~bypass;
  //assign tready = 1'b1;
  genvar i;
  genvar j;
  generate
  for (i = 0; i < MAX_PACKET_SIZE/DATA_WIDTH; i++)
    for (j = 0; j < KEEP_WIDTH; j++)
      assign fif.data[DATA_WIDTH*i+BITS_PER_KEEP*(j+1)-1:DATA_WIDTH*i+BITS_PER_KEEP*j] = keep_acc_pipe[PIPE_LEN-1][i][j] ? data_acc_pipe[PIPE_LEN-1][i][BITS_PER_KEEP*(j+1)-1:BITS_PER_KEEP*j] : '0;
  endgenerate
  assign fif.rule_id = rule_acc_pipe[PIPE_LEN-1][cur_rule];
  assign fif.last = cur_rule == num_rules - 'd1 && fif.valid;
  //assign fif.valid = cur_index == '0;

endmodule