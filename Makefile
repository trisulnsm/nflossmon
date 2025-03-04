CXX = g++
CXXFLAGS_DEBUG = -Wall -Wextra -std=c++17 -g
CXXFLAGS_RELEASE = -Wall -Wextra -std=c++17 -O2
LDFLAGS = -lpcap

SOURCES = main.cpp netflow_processor.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = netflow_loss_monitor

# Default target is debug build
all: debug

debug: CXXFLAGS = $(CXXFLAGS_DEBUG)
debug: $(EXECUTABLE)

release: CXXFLAGS = $(CXXFLAGS_RELEASE)
release: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) 