
SCRIPT_VERSION=v2.0
SCRIPT_AUTHOR=RYDE team

CC=cc
C_FLAGS:=-O3 -flto -Wall -Wextra -Wno-unused-function
C_FLAGS_VERBOSE:=-O3 -flto -Wall -Wextra -Wno-unused-function -DVERBOSE
C_FLAGS_ARM:=-O3 -flto -Wall -Wextra -Wno-unused-function -DOPT_ARM
C_FLAGS_ARM_VERBOSE:=-O3 -flto -Wall -Wextra -Wno-unused-function -DOPT_ARM -DVERBOSE
C_FLAGS_NEON:=-O3 -flto -Wall -Wextra -Wno-unused-function -DOPT_ARM -DUSE_NEON
C_FLAGS_ARM_FOLDED:=-O3 -flto -Wall -Wextra -Wno-unused-function -DOPT_ARM -DUSE_ARM_FOLDED

RANDOMBYTES_SRC:=lib/randombytes/randombytes.c
OPENSSL_PREFIX:=$(shell brew --prefix openssl 2>/dev/null || echo /usr)
RANDOMBYTES_INCLUDE:=-I lib/randombytes -I$(OPENSSL_PREFIX)/include -L$(OPENSSL_PREFIX)/lib -lcrypto

XKCP_SRC:=lib/XKCP
XKCP_SRC_SIMPLE:=$(XKCP_SRC)/SimpleFIPS202.c
XKCP_INCLUDE:=-I$(XKCP_SRC) -I$(XKCP_SRC)/opt64
XKCP_INCLUDE_SIMPLE:=-I $(XKCP_SRC)
XKCP_LINKER:=-L$(XKCP_SRC) -lshake

WRAPPER_SRC:=src/wrapper
WRAPPER_INCLUDE:=-I $(WRAPPER_SRC)

RBC_SRC:=src/rbc-61
RBC_INCLUDE:=-I $(RBC_SRC)

SRC:=src
INCLUDE:=-I src $(RBC_INCLUDE) $(WRAPPER_INCLUDE) $(XKCP_INCLUDE) $(RANDOMBYTES_INCLUDE)

MAIN_RYDE:=src/main.c
BENCH_RYDE:=src/bench.c
KAT_RYDE:=src/PQCgenKAT_sign.c

RYDE_OBJS:=rbc_61_elt.o rbc_61_vec.o rbc_61_vspace.o rbc_61_mat.o rbc_61_mat_fq.o keypair.o signature.o verification.o parsing.o ggm_tree.o sign.o
RYDE_OBJS_VERBOSE:=rbc_61_elt.o rbc_61_vec.o rbc_61_vspace.o rbc_61_mat.o rbc_61_mat_fq.o keypair-verbose.o signature-verbose.o verification-verbose.o parsing.o ggm_tree.o sign.o

# ARM-optimized object lists: ggm_tree and tcith need OPT_ARM define
RYDE_OBJS_ARM:=rbc_61_elt.o rbc_61_vec.o rbc_61_vspace.o rbc_61_mat.o rbc_61_mat_fq.o keypair.o signature.o verification.o parsing.o ggm_tree-arm.o sign.o
RYDE_OBJS_ARM_VERBOSE:=rbc_61_elt.o rbc_61_vec.o rbc_61_vspace.o rbc_61_mat.o rbc_61_mat_fq.o keypair-verbose.o signature-verbose.o verification-verbose.o parsing.o ggm_tree-arm.o sign.o
RYDE_OBJS_NEON:=rbc_61_elt.o rbc_61_vec.o rbc_61_vspace.o rbc_61_mat.o rbc_61_mat_fq.o keypair.o signature.o verification.o parsing.o ggm_tree-neon.o sign.o
# Folded (AddRoundKey-folded ARM Crypto) object list: ggm_tree gets USE_ARM_FOLDED
RYDE_OBJS_ARM_FOLDED:=rbc_61_elt.o rbc_61_vec.o rbc_61_vspace.o rbc_61_mat.o rbc_61_mat_fq.o keypair.o signature.o verification.o parsing.o ggm_tree-folded.o sign.o

# ARM Rijndael-256 assembly and keyschedule objects
ARM_RIJNDAEL_OBJS:=rijndael256_keyschedule.o rijndael256_arm_asm.o rijndael256_neon_asm.o rijndael256_neon_interleaved_asm.o
# Folded Rijndael-256 objects: key schedule + folded encrypt (no EOR asm needed)
FOLDED_RIJNDAEL_OBJS:=rijndael256_keyschedule.o rijndael256_folded_arm.o

LIB_OBJS:=SimpleFIPS202.o randombytes.o

BUILD:=bin/build
BIN:=bin



folders:
	@echo -e "\n### Creating build folders\n"
	mkdir -p $(BUILD)

randombytes.o: folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $(RANDOMBYTES_SRC) $(RANDOMBYTES_INCLUDE) -o $(BUILD)/$@

SimpleFIPS202.o: folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $(XKCP_SRC_SIMPLE) $(XKCP_INCLUDE_SIMPLE) $(XKCP_INCLUDE) $(XKCP_LINKER) -o $(BUILD)/SimpleFIPS202.o

xkcp: folders
	@echo -e "\n### Compiling XKCP\n"
	make -C $(XKCP_SRC)



rbc_%.o: $(RBC_SRC)/rbc_%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $< $(RBC_INCLUDE) $(WRAPPER_INCLUDE) $(XKCP_INCLUDE) -o $(BUILD)/$@

%.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $< $(INCLUDE) -o $(BUILD)/$@

%-verbose.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@ (verbose mode)\n"
	$(CC) $(C_FLAGS_VERBOSE) -c $< $(INCLUDE) -o $(BUILD)/$@


tcith-rijndael.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $< $(INCLUDE) -o $(BUILD)/$@

tcith-sha3.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -D_SHA3_ -c $< $(INCLUDE) -o $(BUILD)/$@

# ARM-optimized Rijndael objects
tcith-arm.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@ (ARM optimized)\n"
	$(CC) $(C_FLAGS_ARM) -c $< $(INCLUDE) -o $(BUILD)/$@

tcith-arm-sha3.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@ (ARM optimized, SHA3)\n"
	$(CC) $(C_FLAGS_ARM) -D_SHA3_ -c $< $(INCLUDE) -o $(BUILD)/$@

ggm_tree-arm.o: $(SRC)/ggm_tree.c | folders
	@echo -e "\n### Compiling $@ (ARM optimized)\n"
	$(CC) $(C_FLAGS_ARM) -c $< $(INCLUDE) -o $(BUILD)/$@

ggm_tree-neon.o: $(SRC)/ggm_tree.c | folders
	@echo -e "\n### Compiling $@ (NEON optimized)\n"
	$(CC) $(C_FLAGS_NEON) -c $< $(INCLUDE) -o $(BUILD)/$@

# Folded (AddRoundKey-folded ARM Crypto) compile rules
tcith-folded.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@ (ARM folded)\n"
	$(CC) $(C_FLAGS_ARM_FOLDED) -c $< $(INCLUDE) -o $(BUILD)/$@

ggm_tree-folded.o: $(SRC)/ggm_tree.c | folders
	@echo -e "\n### Compiling $@ (ARM folded)\n"
	$(CC) $(C_FLAGS_ARM_FOLDED) -c $< $(INCLUDE) -o $(BUILD)/$@

rijndael256_folded_arm.o: $(SRC)/rijndael256_folded_arm.c | folders
	@echo -e "\n### Compiling $@ (Rijndael-256 folded encrypt)\n"
	$(CC) $(C_FLAGS) -c $< $(INCLUDE) -o $(BUILD)/$@

tcith-neon.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@ (NEON optimized)\n"
	$(CC) $(C_FLAGS_NEON) -c $< $(INCLUDE) -o $(BUILD)/$@

ggm_tree-arm-verbose.o: $(SRC)/ggm_tree.c | folders
	@echo -e "\n### Compiling $@ (ARM optimized, verbose)\n"
	$(CC) $(C_FLAGS_ARM_VERBOSE) -c $< $(INCLUDE) -o $(BUILD)/$@

rijndael256_keyschedule.o: $(SRC)/rijndael256_keyschedule.c | folders
	@echo -e "\n### Compiling $@ (Rijndael-256 key schedule)\n"
	$(CC) $(C_FLAGS) -c $< $(INCLUDE) -o $(BUILD)/$@

rijndael256_arm_asm.o: $(SRC)/rijndael256_arm.S | folders
	@echo -e "\n### Assembling $@ (ARM Crypto Extension)\n"
	$(CC) $(C_FLAGS) -c $< -o $(BUILD)/$@

rijndael256_neon_asm.o: $(SRC)/rijndael256_neon.S | folders
	@echo -e "\n### Assembling $@ (NEON TBL/TBX)\n"
	$(CC) $(C_FLAGS) -c $< -o $(BUILD)/$@

rijndael256_neon_interleaved_asm.o: $(SRC)/rijndael256_neon_interleaved.S | folders
	@echo -e "\n### Assembling $@ (NEON interleaved)\n"
	$(CC) $(C_FLAGS) -c $< -o $(BUILD)/$@



all: ryde3f-rijndael-main ryde3f-rijndael-bench ryde3f-rijndael-kat ryde3f-rijndael-verbose ryde3f-sha3-main ryde3f-sha3-bench ryde3f-sha3-kat ryde3f-sha3-verbose ##@Build Build all the project

# --- Reference Rijndael targets (original) ---

.PHONY: ryde3f-rijndael-main
ryde3f-rijndael-main: $(RYDE_OBJS) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build A single example using Rijndael-based commits
	@echo -e "\n### Compiling RYDE-3F (main) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-sha3-main
ryde3f-sha3-main: $(RYDE_OBJS) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build A single example using SHA3-based commits
	@echo -e "\n### Compiling RYDE-3F (main) using SHA3-based commits\n"
	$(CC) $(C_FLAGS) -D_SHA3_ $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-rijndael-bench
ryde3f-rijndael-bench: $(RYDE_OBJS) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build Benchmarks using Rijndael-based commits
	@echo -e "\n### Compiling RYDE-3F (benchmark) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS) $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-sha3-bench
ryde3f-sha3-bench: $(RYDE_OBJS) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build Benchmarks using SHA3-based commits
	@echo -e "\n### Compiling RYDE-3F (benchmark) using SHA3-based commits\n"
	$(CC) $(C_FLAGS) -D_SHA3_ $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-rijndael-kat
ryde3f-rijndael-kat: $(RYDE_OBJS) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build Generate KAT files using Rijndael-based commits: PQCsignKAT_XX.req and PQCsignKAT_XX.rsp
	@echo -e "\n### Compiling RYDE-3F (KATs) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS) $(KAT_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-sha3-kat
ryde3f-sha3-kat: $(RYDE_OBJS) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build Generate KAT files using SHA3-based commits: PQCsignKAT_XX.req and PQCsignKAT_XX.rsp
	@echo -e "\n### Compiling RYDE-3F (KATs) using SHA3-based commits\n"
	$(CC) $(C_FLAGS) -D_SHA3_ $(KAT_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-rijndael-verbose
ryde3f-rijndael-verbose: $(RYDE_OBJS_VERBOSE) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build Generate intermediate values of a single example using Rijndael-based commits
	@echo -e "\n### Compiling RYDE-3F (verbose mode) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS_VERBOSE) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-sha3-verbose
ryde3f-sha3-verbose: $(RYDE_OBJS_VERBOSE) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build Generate intermediate values of a single example using SHA3-based commits
	@echo -e "\n### Compiling RYDE-3F (verbose mode) using SHA3-based commits\n"
	$(CC) $(C_FLAGS_VERBOSE) -D_SHA3_ $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

# --- ARM-optimized Rijndael-256 targets ---

.PHONY: ryde3f-arm-main
ryde3f-arm-main: $(RYDE_OBJS_ARM) tcith-arm.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build A single example using ARM-optimized Rijndael
	@echo -e "\n### Compiling RYDE-3F (main) using ARM-optimized Rijndael\n"
	$(CC) $(C_FLAGS_ARM) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-bench
ryde3f-arm-bench: $(RYDE_OBJS_ARM) tcith-arm.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build Benchmarks using ARM-optimized Rijndael
	@echo -e "\n### Compiling RYDE-3F (benchmark) using ARM-optimized Rijndael\n"
	$(CC) $(C_FLAGS_ARM) $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-folded-bench
ryde3f-arm-folded-bench: $(RYDE_OBJS_ARM_FOLDED) tcith-folded.o $(FOLDED_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build Benchmarks using AddRoundKey-folded ARM Rijndael
	@echo -e "\n### Compiling RYDE-3F (benchmark) using folded ARM Rijndael\n"
	$(CC) $(C_FLAGS_ARM_FOLDED) $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-folded-kat
ryde3f-arm-folded-kat: $(RYDE_OBJS_ARM_FOLDED) tcith-folded.o $(FOLDED_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build KAT using AddRoundKey-folded ARM Rijndael
	@echo -e "\n### Compiling RYDE-3F (KATs) using folded ARM Rijndael\n"
	$(CC) $(C_FLAGS_ARM_FOLDED) $(KAT_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-kat
ryde3f-arm-kat: $(RYDE_OBJS_ARM) tcith-arm.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build Generate KAT files using ARM-optimized Rijndael
	@echo -e "\n### Compiling RYDE-3F (KATs) using ARM-optimized Rijndael\n"
	$(CC) $(C_FLAGS_ARM) $(KAT_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-verbose
ryde3f-arm-verbose: $(RYDE_OBJS_ARM_VERBOSE) tcith-arm.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build Verbose output using ARM-optimized Rijndael
	@echo -e "\n### Compiling RYDE-3F (verbose mode) using ARM-optimized Rijndael\n"
	$(CC) $(C_FLAGS_ARM_VERBOSE) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

# --- NEON TBL/TBX targets ---

.PHONY: ryde3f-neon-main
ryde3f-neon-main: $(RYDE_OBJS_NEON) tcith-neon.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders
	@echo -e "\n### Compiling RYDE-3F (main) using NEON Rijndael\n"
	$(CC) $(C_FLAGS_NEON) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-neon-bench
ryde3f-neon-bench: $(RYDE_OBJS_NEON) tcith-neon.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders
	@echo -e "\n### Compiling RYDE-3F (benchmark) using NEON Rijndael\n"
	$(CC) $(C_FLAGS_NEON) $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-sha3-main
ryde3f-arm-sha3-main: $(RYDE_OBJS_ARM) tcith-arm-sha3.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build SHA3 example with ARM-optimized Rijndael for seed expansion
	@echo -e "\n### Compiling RYDE-3F (main, SHA3) using ARM-optimized Rijndael\n"
	$(CC) $(C_FLAGS_ARM) -D_SHA3_ $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde3f-arm-sha3-bench
ryde3f-arm-sha3-bench: $(RYDE_OBJS_ARM) tcith-arm-sha3.o $(ARM_RIJNDAEL_OBJS) $(LIB_OBJS) | xkcp folders ##@Build SHA3 benchmarks with ARM-optimized Rijndael for seed expansion
	@echo -e "\n### Compiling RYDE-3F (benchmark, SHA3) using ARM-optimized Rijndael\n"
	$(CC) $(C_FLAGS_ARM) -D_SHA3_ $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: clean
clean: ##@Miscellaneous Clean data
	make -C $(XKCP_SRC) clean
	rm -f PQCsignKAT_*
	rm -f vgcore.*
	rm -rf ./bin



.PHONY: help
HELP_FUN = \
    %help; while(<>){push@{$$help{$$2//'options'}},[$$1,$$3] \
    if/^([\w-_]+)\s*:.*\#\#(?:@(\w+))?\s(.*)$$/}; \
    print"$$_:\n", map"  \033[37m$$_->[0]\033[0m".(" "x(25-length($$_->[0])))."$$_->[1]\n",\
    @{$$help{$$_}},"\n" for keys %help; \

help: ##@Miscellaneous Show this help
	@echo -e "Usage: make [target] ..."
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)
	@echo -e "Written by \033[36m$(SCRIPT_AUTHOR)\033[0m, version \033[37m$(SCRIPT_VERSION)\033[0m"
	@echo -e "Please report any bug or error to the authors."
