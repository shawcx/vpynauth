PLUGIN=vpynauth

CC = gcc

CFLAGS = $(shell python3-config --cflags)
LIBS = $(shell python3-config --embed --libs)

OBJS = src/$(PLUGIN).o
OUT  = $(PLUGIN).so

all: $(OUT)

$(OUT): $(OBJS)
	$(CC) --shared $< $(LIBS) -o $@

src/%.o: src/%.c
	$(CC) -c $(CFLAGS) -fPIC $< -o $@

clean:
	@rm -f $(OBJS)

distclean: clean
	@rm -f $(OUT)
