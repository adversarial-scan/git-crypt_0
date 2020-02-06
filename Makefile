LDFLAGS := -lcrypto

OBJFILES = git-crypt.o commands.o crypto.o util.o

all: git-crypt

git-crypt: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o git-crypt

.PHONY: all clean
