module bitcoin_hash (input logic        clk, rst_n, start,
                     input logic [15:0] input_addr, hash_addr,
                    output logic        done, memory_clk, enable_write,
                    output logic [15:0] memory_addr,
                    output logic [31:0] memory_write_data,
                     input logic [31:0] memory_read_data);

parameter num_nonces = 16;

// FSM state variables
enum logic [3:0] {IDLE, READ, BLOCK1, BLOCK2, COMPUTE1, COMPUTE2, COMPUTE3, PROCESS, WRITE} state;

// local variables
logic [31:0] h[8];
// orig_h stores the first 16 words hash output
// copy_h stores the hash output for each of the nonces
// final_h stores the final output to be written to memory
logic [31:0] orig_h[8], copy_h[16][8], final_h[num_nonces]; // stores the hash output for the first 16 words
logic [31:0] w1[16]; // holds the first block's words
logic [31:0] w2[16]; // holds the second block's words
logic [31:0] w3[16][16]; // holds the word expansion for each nonce all at once
logic [31:0] S0,S1;
logic [31:0] A[16], B[16], C[16], D[16], E[16], F[16], G[16], H[16];
// j is the index while looping through 64
// m is the index of the hash output to write to memory
logic [7:0] j, m;
logic [31:0] n; // n is the nonce counter
logic [15:0] offset; // offset from the input and output address to write to
logic [15:0] present_addr;
logic [31:0] present_write_data;
logic [512:0] data_read;
logic [63:0] length;


parameter int k[64] = '{
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


// optimized word expansion
function logic [31:0] wtnew_w1(); 
	logic [31:0] s0, s1;
	s0 = ror(w1[1],7) ^ ror(w1[1],18) ^ (w1[1]>>3);
	s1 = ror(w1[14],17) ^ ror(w1[14],19) ^ (w1[14]>>10);
	wtnew_w1 = w1[0] + s0 + w1[9] + s1;
endfunction

function logic [31:0] wtnew_w3(input logic[4:0] n); 
	logic [31:0] s0, s1;
	s0 = ror(w3[n][1],7) ^ ror(w3[n][1],18) ^ (w3[n][1]>>3);
	s1 = ror(w3[n][14],17) ^ ror(w3[n][14],19) ^ (w3[n][14]>>10);
	wtnew_w3 = w3[n][0] + s0 + w3[n][9] + s1;
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

// right rotation function
function logic [31:0] ror (input logic [31:0] in,
											input logic [7:0] s);
begin
	ror = (in >> s) | (in << (32 - s));
end
endfunction

// BITCOIN_HASH FSM
always_ff @(posedge clk, negedge rst_n)
begin
	if (!rst_n) begin
		state <= IDLE;
		enable_write <= 1'b0;
  	end 
	else begin
		case (state)
            IDLE: begin
						$display("IDLE\n");
                if (start) begin

                    // length for the w2
                    length <= 32'd640;

                    //initialize the hash values
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
                    j<= 0;
                    n <= 0;
                    state <= READ;
                end
                else begin
                    enable_write <= 1'b0;
                    state <= IDLE;
                end
            end

            // READ, BLOCK1, COMPUTE1 store the initial hash for the first 16 words
            // read the 19 words from the input address
            READ: begin
					$display("READ\n");

                // if reading the first 16 words -- the first block
                if (j < 17) begin
                    w1[j-1] <= memory_read_data;
                    offset <= offset + 1;
                    j <= j + 1;
                    state <= READ;
                end

                // if reading the last 3 words -- the second block
                else if (j < 20 && j >= 17)begin
							$display("j is 17-20\n");
                    w2[j-17] <= memory_read_data;
                    offset <= offset + 1;
                    j <= j + 1;
                    state <= READ;
                end

                // all words have been read
                else begin
                    // add to w2 the padding and the length
                    w2[3] <= 32'h0; //going to be nonce
                    w2[4] <= 32'h80000000;
                    w2[5] <= 32'h0;
                    w2[6] <= 32'h0;
                    w2[7] <= 32'h0;
                    w2[8] <= 32'h0;
                    w2[9] <= 32'h0;
                    w2[10] <= 32'h0;
                    w2[11] <= 32'h0;
                    w2[12] <= 32'h0;
                    w2[13] <= 32'h0;
                    w2[14] <= 32'h0;
                    w2[15] <= 32'h00000280;
                    state <= BLOCK1;
                end

            end

            //load the initial hash values
            BLOCK1: begin
					$display("BLOCK1\n");

                A[0] <= h[0];
                B[0] <= h[1];
                C[0] <= h[2];
                D[0] <= h[3];
                E[0] <= h[4];
                F[0] <= h[5];
                G[0] <= h[6];
                H[0] <= h[7];

                j <= 0; //reusing j for hashing
					 
					 state <= COMPUTE1;
            end

            // create the hash output of the first 16 words
            COMPUTE1: begin
					$display("COMPUTE1\n");
               if(j < 64) begin
						{A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]} <= sha256_op(.a(A[0]), .b(B[0]), .c(C[0]), .d(D[0]), .e(E[0]), .f(F[0]), .g(G[0]), .h(H[0]), .w(w1[0]), .t(j));
						for (int n = 0; n < 15; n++) begin
							w1[n] <= w1[n+1];
						end
						w1[15] <= wtnew_w1();
						j <= j + 1;
						state <= COMPUTE1;
					end
				// save the newly computed hash values
					else begin
						orig_h[0] <= h[0] + A[0];
						orig_h[1] <= h[1] + B[0];
						orig_h[2] <= h[2] + C[0];
						orig_h[3] <= h[3] + D[0];
						orig_h[4] <= h[4] + E[0];
						orig_h[5] <= h[5] + F[0];
						orig_h[6] <= h[6] + G[0];
						orig_h[7] <= h[7] + H[0];
						j <= 0;
						state <= BLOCK2;
					end
            end

            // BLOCK2, COMPUTE2, PROCESS, COMPUTE3, WRITE creates the nonce hash values
            // load the original hash output from the 16 words
            BLOCK2: begin
					$display("BLOCK2\n");
					j <= 0;

					for(int x = 0; x < 16; x++) begin
						copy_h[x][0] <= orig_h[0];
						copy_h[x][1] <= orig_h[1];
						copy_h[x][2] <= orig_h[2];
						copy_h[x][3] <= orig_h[3];
						copy_h[x][4] <= orig_h[4];
						copy_h[x][5] <= orig_h[5];
						copy_h[x][6] <= orig_h[6];
						copy_h[x][7] <= orig_h[7];
					end
					
					for(int x = 0; x < 16; x++) begin
						A[x] <= orig_h[0];
						B[x] <= orig_h[1];
						C[x] <= orig_h[2];
						D[x] <= orig_h[3];
						E[x] <= orig_h[4];
						F[x] <= orig_h[5];
						G[x] <= orig_h[6];
						H[x] <= orig_h[7];
					end
					
					for(int x = 0; x < 16; x++) begin
						for(int y = 0; y < 16; y++) begin
							if(y == 3) begin
								w3[x][y] <= x;
							end
							else begin
								w3[x][y] <= w2[y];
							end
						end
					end
					state <= COMPUTE2;
            end

            // create the hash values for a nonce value
            COMPUTE2: begin
					$display("COMPUTE2\n");
					for(int x = 0;x < 16; x++) begin
						if(j < 64) begin
							{A[x], B[x], C[x], D[x], E[x], F[x], G[x], H[x]} <= sha256_op(.a(A[x]), .b(B[x]), .c(C[x]), .d(D[x]), .e(E[x]), .f(F[x]), .g(G[x]), .h(H[x]), .w(w3[x][0]), .t(j));
							for (int n = 0; n < 15; n++) begin
								w3[x][n] <= w3[x][n+1];
							end
							w3[x][15] <= wtnew_w3(x);
							j <= j + 1;
							state <= COMPUTE2;
						end
					
						// save the newly computed hash values
						else begin
							copy_h[x][0] <= copy_h[x][0] + A[x];
							copy_h[x][1] <= copy_h[x][1] + B[x];
							copy_h[x][2] <= copy_h[x][2] + C[x];
							copy_h[x][3] <= copy_h[x][3] + D[x];
							copy_h[x][4] <= copy_h[x][4] + E[x];
							copy_h[x][5] <= copy_h[x][5] + F[x];
							copy_h[x][6] <= copy_h[x][6] + G[x];
							copy_h[x][7] <= copy_h[x][7] + H[x];
							j <= 0;
							state <= PROCESS;
						end
					end
            end

            // create the block input before a final round of sha
            PROCESS: begin
					$display("PROCESS\n");
					 for(int x = 0; x < 16; x++) begin
						w3[x][0] <= copy_h[x][0];
						w3[x][1] <= copy_h[x][1];
						w3[x][2] <= copy_h[x][2];
						w3[x][3] <= copy_h[x][3];
						w3[x][4] <= copy_h[x][4];
						w3[x][5] <= copy_h[x][5];
						w3[x][6] <= copy_h[x][6];
						w3[x][7] <= copy_h[x][7];
						w3[x][8] <= 32'h80000000;
						w3[x][9] <= 32'h0;
						w3[x][10] <= 32'h0;
						w3[x][11] <= 32'h0;
						w3[x][12] <= 32'h0;
						w3[x][13] <= 32'h0;
						w3[x][14] <= 32'h0;
						w3[x][15] <= 32'h00000100;
					 end
					 
					 for(int x = 0; x < 16; x++) begin
						copy_h[x][0] <= 32'h6a09e667;
						copy_h[x][1] <= 32'hbb67ae85;
						copy_h[x][2] <= 32'h3c6ef372;
						copy_h[x][3] <= 32'ha54ff53a;
						copy_h[x][4] <= 32'h510e527f;
						copy_h[x][5] <= 32'h9b05688c;
						copy_h[x][6] <= 32'h1f83d9ab;
						copy_h[x][7] <= 32'h5be0cd19;
					 end

					 for(int x = 0; x < 16; x++) begin
						A[x] <= 32'h6a09e667;
						B[x] <= 32'hbb67ae85;
						C[x] <= 32'h3c6ef372;
						D[x] <= 32'ha54ff53a;
						E[x] <= 32'h510e527f;
						F[x] <= 32'h9b05688c;
						G[x] <= 32'h1f83d9ab;
						H[x] <= 32'h5be0cd19;
					 end

                j <= 0;

                state <= COMPUTE3;

            end

            // create hash output for a nonce value
            COMPUTE3: begin
					$display("COMPUTE3\n");
					for(int x = 0; x < 16; x++) begin
						if(j < 64) begin
							{A[x], B[x], C[x], D[x], E[x], F[x], G[x], H[x]} <= sha256_op(.a(A[x]), .b(B[x]), .c(C[x]), .d(D[x]), .e(E[x]), .f(F[x]), .g(G[x]), .h(H[x]), .w(w3[x][0]), .t(j));
							for (int n = 0; n < 15; n++) begin
								w3[x][n] <= w3[x][n+1];
							end
							w3[x][15] <= wtnew_w3(x);
							j <= j + 1;
							state <= COMPUTE3;
						end
						else begin
							
							final_h[x] <= copy_h[x][0] + A[x];
							j <= 0;
							m <= 0;
							enable_write <= 1'b1;
							present_addr <= hash_addr;
							state <= WRITE;
						end
					end	
            end


            // all nonce hashes have been computed, write to output address
            WRITE: begin
					$display("WRITE\n");
                // write each hash value into memory
					offset <= m;
					if(m < 16) begin
						present_write_data <= final_h[m];
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

// Generate done when bitcoin_hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
