`resetall `timescale 1ns / 1ps `default_nettype none

module hds_shim_layer #(
    // DMA interface configuration
    parameter DMA_ADDR_WIDTH = 64,
    parameter DMA_IMM_ENABLE = 0,
    parameter DMA_IMM_WIDTH = 32,
    parameter DMA_LEN_WIDTH = 16,
    parameter DMA_TAG_WIDTH = 16,
    parameter RAM_SEL_WIDTH = 4,
    parameter RAM_ADDR_WIDTH = 16,
    parameter RAM_SEG_COUNT = 2,
    parameter RAM_SEG_DATA_WIDTH = 256 * 2 / RAM_SEG_COUNT,
    parameter RAM_SEG_BE_WIDTH = RAM_SEG_DATA_WIDTH / 8,
    parameter RAM_SEG_ADDR_WIDTH = RAM_ADDR_WIDTH - $clog2(RAM_SEG_COUNT * RAM_SEG_BE_WIDTH),
    parameter RAM_PIPELINE = 2,
    // Ethernet interface configuration ( direct, async )
    parameter AXIS_DATA_WIDTH = 512,
    parameter AXIS_KEEP_WIDTH = AXIS_DATA_WIDTH / 8,
    parameter AXIS_TX_USER_WIDTH = TX_TAG_WIDTH + 1,
    parameter AXIS_RX_USER_WIDTH = (PTP_TS_ENABLE ? PTP_TS_WIDTH : 0) + 1,
    parameter AXIS_RX_USE_READY = 0,

    // Ethernet interface configuration ( direct, sync )
    parameter AXIS_SYNC_DATA_WIDTH = AXIS_DATA_WIDTH,
    parameter AXIS_SYNC_KEEP_WIDTH = AXIS_SYNC_DATA_WIDTH / 8,
    parameter AXIS_SYNC_TX_USER_WIDTH = AXIS_TX_USER_WIDTH,
    parameter AXIS_SYNC_RX_USER_WIDTH = AXIS_RX_USER_WIDTH,

    // Ethernet interface configuration ( interface )
    parameter AXIS_IF_DATA_WIDTH = AXIS_SYNC_DATA_WIDTH * 2 ** $clog2(PORTS_PER_IF),
    parameter AXIS_IF_KEEP_WIDTH = AXIS_IF_DATA_WIDTH / 8,
    parameter AXIS_IF_TX_ID_WIDTH = 12,
    parameter AXIS_IF_RX_ID_WIDTH = PORTS_PER_IF > 1 ? $clog2(PORTS_PER_IF) : 1,
    parameter AXIS_IF_TX_DEST_WIDTH = $clog2(PORTS_PER_IF) + 4,
    parameter AXIS_IF_RX_DEST_WIDTH = 8,
    parameter AXIS_IF_TX_USER_WIDTH = AXIS_SYNC_TX_USER_WIDTH,
    parameter AXIS_IF_RX_USER_WIDTH = AXIS_SYNC_RX_USER_WIDTH
) (
    input wire clk,
    input wire rst,

    /*
				 * DMA RAM interface ( data )
				 */
    // input  wire [ RAM_SEG_COUNT*RAM_SEL_WIDTH-1:0 ]         data_dma_ram_wr_cmd_sel,
    // input  wire [ RAM_SEG_COUNT*RAM_SEG_BE_WIDTH-1:0 ]      data_dma_ram_wr_cmd_be,
    // input  wire [ RAM_SEG_COUNT*RAM_SEG_ADDR_WIDTH-1:0 ]    data_dma_ram_wr_cmd_addr,
    // input  wire [ RAM_SEG_COUNT*RAM_SEG_DATA_WIDTH-1:0 ]    data_dma_ram_wr_cmd_data,
    // input  wire [ RAM_SEG_COUNT-1:0 ]                       data_dma_ram_wr_cmd_valid,
    // output wire [ RAM_SEG_COUNT-1:0 ]                       data_dma_ram_wr_cmd_ready,
    // output wire [ RAM_SEG_COUNT-1:0 ]                       data_dma_ram_wr_done,

    // input  wire [ RAM_SEG_COUNT*RAM_SEL_WIDTH-1:0 ]         data_dma_ram_rd_cmd_sel,
    // input  wire [ RAM_SEG_COUNT*RAM_SEG_ADDR_WIDTH-1:0 ]    data_dma_ram_rd_cmd_addr,


    input wire [RAM_SEG_COUNT*RAM_SEG_ADDR_WIDTH-1:0] data_dma_ram_rd_cmd_addr,
    input  wire [ RAM_SEG_COUNT-1:0 ]                     data_dma_ram_rd_cmd_valid,// suggests if current transaction is over

    input wire [                   RAM_SEG_COUNT-1:0] data_dma_ram_rd_resp_valid,
    input wire [RAM_SEG_COUNT*RAM_SEG_DATA_WIDTH-1:0] data_dma_ram_rd_resp_data,

    output reg [                   RAM_SEG_COUNT-1:0] data_dma_ram_rd_resp_valid_split,
    output reg [RAM_SEG_COUNT*RAM_SEG_DATA_WIDTH-1:0] data_dma_ram_rd_resp_data_split

);

  // reg [ RAM_SEG_COUNT-1:0 ]                       data_dma_ram_rd_resp_valid_split_next;
  // reg [ RAM_SEG_COUNT*RAM_SEG_DATA_WIDTH-1:0 ]    data_dma_ram_rd_resp_data_split_next;
  // reg counter = 0, counter_next;// 0~1

  // always @( * ) begin
  // 				data_dma_ram_rd_resp_data_split_next  = data_dma_ram_rd_resp_data_split;
  // 				data_dma_ram_rd_resp_valid_split_next = data_dma_ram_rd_resp_valid_split;
  // 				counter_next                          = counter;
  // 				if ( counter ) begin // needs to cut, valid = 0

  // 				end
  // 				else begin

  // 				end

  // end

  // always @( posedge clk ) begin
  // 				data_dma_ram_rd_resp_data_split  <= data_dma_ram_rd_resp_data_split_next;
  // 				data_dma_ram_rd_resp_valid_split <= data_dma_ram_rd_resp_valid_split_next;
  // 				if ( rst ) begin
  // 								counter                          <= 0;
  // 								data_dma_ram_rd_resp_data_split  <= data_dma_ram_rd_resp_data;
  // 								data_dma_ram_rd_resp_valid_split <= data_dma_ram_rd_resp_valid;
  // 				end
  // end










endmodule

`resetall
