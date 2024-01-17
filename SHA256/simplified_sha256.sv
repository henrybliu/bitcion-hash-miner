module simplified_sha256 #(parameter integer NUM_OF_WORDS = 40)(
 input logic  clk, rst_n, start,
 input logic  [15:0] input_addr, hash_addr,
 output logic done, memory_clk, enable_write,
 output logic [15:0] memory_addr,
 output logic [31:0] memory_write_data,
 input logic [31:0] memory_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

// Local variables
logic [31:0] w[16];
// logic [31:0] w[16];
logic [31:0] S0,S1;
logic [31:0] h[8];
logic [31:0] A, B, C, D, E, F, G, H;
// i is the current block
// j is the current word within a block
// m is the index of the hash function to write
// x is the round of compression
logic [ 7:0] i, j, m, x; 
logic [15:0] offset; // offset from the input and output address to write to
logic [ 7:0] num_blocks;
logic [15:0] present_addr;
logic [31:0] present_write_data;
logic [512:0] data_read;
logic [63:0] length;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Generate request to memory
// for reading from memory to get original w
// for writing final computed has value
assign memory_clk = clk;
assign memory_addr = present_addr + offset;
assign memory_we = enable_write;
assign memory_write_data = present_write_data;


// calculate total number of blocks and the length in bits of the input w
assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
assign length = NUM_OF_WORDS * 32;


// Note : Function defined are for reference purpose.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);
	determine_num_blocks = ((NUM_OF_WORDS * 32) / 512) + 1;
	// need to increment number of needed blocks if the second to last block needs padding but not the length
	if (((NUM_OF_WORDS % 16) +2) == 16) begin
		determine_num_blocks++;
	end
endfunction


// optimized word expansion
function logic [31:0] wtnew(); 
	logic [31:0] s0, s1;
	s0 = ror(w[1],7) ^ ror(w[1],18) ^ (w[1]>>3);
	s1 = ror(w[14],17) ^ ror(w[14],19) ^ (w[14]>>10);
	wtnew = w[0] + s0 + w[9] + s1;
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
	S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
	maj = (a & b) ^ (a & c) ^ (b & c);
	t2 = S0 + maj;
	S1 = ror(e,6) ^ ror(e,11) ^ ror(e, 25);
	ch = (e & f) ^ ((~e) & g);
	t1 = h + S1 + ch + k[t] + w;
	sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};	
end
endfunction


// Right rotation function
function logic [31:0] ror(input logic [31:0] in,
                                  input logic [7:0] s);
begin
	ror = (in >> s) | (in << (32 - s));
end
endfunction


// SHA-256 FSM 
always_ff @(posedge clk, negedge rst_n)
begin
	if (!rst_n) begin
		state <= IDLE;
		enable_write <= 1'b0;
  	end 
	else begin
		case (state)

			// initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
			IDLE: begin 
				if(start) begin 
					// initialize hash values
					h[0] <= 32'h6a09e667;
					h[1] <= 32'hbb67ae85;
					h[2] <= 32'h3c6ef372;
					h[3] <= 32'ha54ff53a;
					h[4] <= 32'h510e527f;
					h[5] <= 32'h9b05688c;
					h[6] <= 32'h1f83d9ab;
					h[7] <= 32'h5be0cd19;
					
					// initialize local variables
					offset <= 0;
					present_addr <= input_addr;
					enable_write <= 1'b0;
					i <= 0;
					j<= 0;
					x<=0;
					present_write_data <= 32'h0;
					state <= READ;
				end
				else begin
						enable_write <= 1'b0;
						state <= IDLE;
				end
			end

			// read a single block from memory
			READ: begin
				// if the second to last block needs padding but not the length
				if (((NUM_OF_WORDS % 16) +2) == 16) begin
					// if first block
					if (i == 0) begin
						// populate w with the words read from memory
						if (j < 16) begin
								w[j-1] <= memory_read_data;
								offset <= offset + 1;
								j <= j + 1;
								state <= READ;
						end
						
						else begin
								w[j-1] <= memory_read_data;
								state <= BLOCK;
						end
					end
					
					// if second block
					else if (i == num_blocks -2) begin
						// only read the remaining words in memory
						if (j <= (NUM_OF_WORDS % 16)) begin
								w[j-1] <= memory_read_data;
								offset <= offset + 1;
								j <= j + 1;
								state <= READ;
						end
						// add the padding to the last two values of w
						else begin
							w[14] <= 32'h80000000;
							w[15] <= 32'h0;
							state <= BLOCK;
						end
					end
					
					// if third block - add padding of 32'h0 and the input w length
					else if (i == num_blocks -1) begin
						w[0] <= 32'h0;
						w[1] <= 32'h0;
						w[2] <= 32'h0;
						w[3] <= 32'h0;
						w[4] <= 32'h0;
						w[5] <= 32'h0;
						w[6] <= 32'h0;
						w[7] <= 32'h0;
						w[8] <= 32'h0;
						w[9] <= 32'h0;
						w[10] <= 32'h0;
						w[11] <= 32'h0;
						w[12] <= 32'h0;
						w[13] <= 32'h0;
						w[14] <= length[63:32];
						w[15] <= length[31:0];
						state <= BLOCK;
						
					end
					
					// all blocks have been read
					else begin
						m <= 0;
						enable_write <= 1'b1;
						present_addr <= hash_addr;
						state <= WRITE;
					end		
				end

				// the second to last block is just the words in the input message
				else begin	
					// if not in the last block - read the words from memory into message
					if (i < num_blocks-1) begin
						if(j < 16) begin
							w[j-1] <= memory_read_data;
							offset <= offset + 1;
							j <= j + 1;
							state <= READ;
						end
						else begin
							w[j-1] <= memory_read_data;
							state <= BLOCK;
						end;
					end

					// if in the last block
					else if (i == num_blocks-1) begin
						// read the remaining words into w from memory
						if(j <= (NUM_OF_WORDS % 16)) begin
							w[j-1] <= memory_read_data;
							offset <= offset + 1;
							j <= j + 1;
							state <= READ;
						end
						// add padding to w
						else if((j < 15) && (j > NUM_OF_WORDS % 16)) begin
							if(j == (NUM_OF_WORDS % 16)+1) begin
								w[j-1] <= 32'h80000000;
								j <= j + 1;
								state <= READ;
							end
							else begin
								w[j-1] <= 32'h0;
								j <= j + 1;
								state <= READ;
							end
						end
						// save the length to the last two values of w
						else begin
							w[14] <= length[63:32];
							w[15] <= length[31:0];
							state <= BLOCK;
						end
					end

					// all blocks have been read
					else begin
						m <= 0;
						enable_write <= 1'b1;
						present_addr <= hash_addr;
						state <= WRITE;
					end
				end
			end

			// save the w read from the input w into w
			BLOCK: begin
				A <= h[0];
				B <= h[1];
				C <= h[2];
				D <= h[3];
				E <= h[4];
				F <= h[5];
				G <= h[6];
				H <= h[7];
				
				i<= i+1;
				x<=0;

				state <= COMPUTE;
			end

				
			// perform 64 rounds of compression and update the hash values
			COMPUTE: begin
				// 64 processing rounds steps for 512-bit block
				if(x < 64) begin
					{A, B, C, D, E, F, G, H} <= sha256_op(.a(A), .b(B), .c(C), .d(D), .e(E), .f(F), .g(G), .h(H), .w(w[0]), .t(x));
					for (int n = 0; n < 15; n++) begin
						w[n] <= w[n+1];
					end
					w[15] <= wtnew();
					x <= x + 1;
					state <= COMPUTE;
				end
					
				// save the newly computed hash values
				else begin
					h[0] <= h[0] + A;
					h[1] <= h[1] + B;
					h[2] <= h[2] + C;
					h[3] <= h[3] + D;
					h[4] <= h[4] + E;
					h[5] <= h[5] + F;
					h[6] <= h[6] + G;
					h[7] <= h[7] + H;
					j <= 0;
					state <= READ;
				end
			end

			// write final hash values back into memory
			WRITE: begin
				// write each hash value into memory
				offset <= m;
				if(m < 8) begin
					present_write_data <= h[m];
					m <= m + 1;
					state <= WRITE;
				end
				// all hash values have been written into memory
				else begin
					offset <= 0;
					m <= 0;
					enable_write <= 1'b0;
					state <= IDLE;
				end
			end
		endcase
	end
	
end
// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule