module axis_full_matcher #(
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
) (
    input aclk,
    fclk,
    rst,

    input [DATA_WIDTH-1:0] tdata_rx,
    input tvalid_rx,
    input [KEEP_WIDTH-1:0] tkeep_rx,
    input tlast_rx,
    output tready_rx,

    output [DATA_WIDTH-1:0] tdata_tx,
    output tvalid_tx,
    output [KEEP_WIDTH-1:0] tkeep_tx,
    output tlast_tx,
    input tready_tx
);

  full_matcher_if fif ();

  wire tready_bypass;
  wire [DATA_WIDTH-1:0] tdata_bypass;
  wire tvalid_bypass;
  wire [KEEP_WIDTH-1:0] tkeep_bypass;
  wire tlast_bypass;

  (* DONT_TOUCH = "yes" *)
  axi_fifo_rx #(
      .DATA_WIDTH(DATA_WIDTH)
  ) fm_rx (
      .aclk(aclk),
      .fclk(fclk),
      .rst(rst),
      .tdata(tdata_rx),
      .tkeep(tkeep_rx),
      .tvalid(tvalid_rx),
      .tready(tready_rx),
      .tlast(tlast_rx),
      .fif(fif),
      .tready_bypass(tready_bypass),
      .tdata_bypass(tdata_bypass),
      .tvalid_bypass(tvalid_bypass),
      .tkeep_bypass(tkeep_bypass),
      .tlast_bypass(tlast_bypass)
  );
  (* DONT_TOUCH = "yes" *)
  full_matcher f_m (
      fclk,
      ~rst,
      fif
  );
  (* DONT_TOUCH = "yes" *)
  axi_fifo_tx #(
      .DATA_WIDTH(DATA_WIDTH)
  ) fm_tx (
      .aclk(aclk),
      .fclk(fclk),
      .rst(rst),
      .tdata(tdata_tx),
      .tkeep(tkeep_tx),
      .tvalid(tvalid_tx),
      .tlast(tlast_tx),
      .tready(tready_tx),
      .fif(fif),
      .tready_bypass(tready_bypass),
      .tdata_bypass(tdata_bypass),
      .tvalid_bypass(tvalid_bypass),
      .tkeep_bypass(tkeep_bypass),
      .tlast_bypass(tlast_bypass)
  );

endmodule
