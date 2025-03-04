CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -g
LDFLAGS = -lpcap

SOURCES = main.cpp netflow_processor.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = netflow_loss_monitor

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) 