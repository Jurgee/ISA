CXX = g++
CXXFLAGS = -std=c++2a -Wall -Wextra -Wpedantic -Werror -g

SRCS = $(wildcard *.cpp)
OBJS := $(patsubst %.cpp,build/%.o,$(SRCS))
DEPS := $(patsubst %.cpp,build/%.d,$(SRCS))

TARGET = dhcp-stats
LIBS = -lpcap -lncurses

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

build/%.o: %.cpp | build
	$(CXX) $(CXXFLAGS) -MMD -MP -MF build/$*.d -c $< -o $@

build:
	mkdir -p $@

-include $(DEPS)

clean:
	$(RM) -r build $(TARGET)
