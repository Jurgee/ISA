CXX = g++
CXXFLAGS = -std=c++2a -Wall -Wextra -Wpedantic

SRCS = $(wildcard *.cpp)
OBJS := $(SRCS:%.cpp=%.o)
DEPS := $(SRCS:%.cpp=%.d)

TARGET = dhcp-stats
LIBS = -lpcap

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

%.o: %.cpp %.d %.h
	$(CXX) -MT $@ -MMD -MP -MF $*.d $(CXXFLAGS) -c $(OUTPUT_OPTION) $<
$(DEPS):
include $(wildcard $(DEPS))

clean:
	$(RM) $(OBJS) $(TARGET)
