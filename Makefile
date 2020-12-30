#defination for compiler 
CC:= g++ -std=c++11 -fPIC

#defination for compiler flag
CFLAG:= -g -Wall -Werror -O3 -fopenmp

SRCDIR:= src
DEMODIR:= demo
BUILDFLDR:= build
PALISADEDIR:= /usr/local/palisade
export CPLUS_INCLUDE_PATH:=$(PALISADEDIR)/include
INCLUDES:= $(shell find $(PALISADEDIR)/include -name "pke" -o -name "core" -o -name "cereal" | sed -e 's/^/-I /'| xargs)
LINKDIR:= -L$(PALISADEDIR)/lib

OBJDIR := build

SRCOBJS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(wildcard $(SRCDIR)/*.cpp))
DEMOOBJS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(wildcard $(DEMODIR)/*.cpp))
DEMOOBJS+= $(patsubst %.o, %, $(DEMOOBJS))

#build for src files
$(OBJDIR)/$(SRCDIR)/%.o : $(SRCDIR)/%.cpp $(SRCDIR)/%.h | $(OBJDIR)/$(SRCDIR)
	$(CC) $(CFLAG) $(INCLUDES) -I $(SRCDIR) -c $< -o $@

$(OBJDIR)/$(SRCDIR)/%.o : $(SRCDIR)/%.cpp | $(OBJDIR)/$(SRCDIR)
	$(CC) $(CFLAG) $(INCLUDES) -I $(SRCDIR) -c $< -o $@
	
#build for demo files
$(OBJDIR)/$(DEMODIR)/%.o : $(DEMODIR)/%.cpp | $(OBJDIR)/$(DEMODIR)
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@

#Link the demo with libraries
$(OBJDIR)/$(DEMODIR)/%: $(OBJDIR)/$(DEMODIR)/%.o $(SRCOBJS)
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEpke_static -lPALISADEcore_static /usr/lib/gcc/x86_64-linux-gnu/7/libquadmath.a
		 
all : $(SRCOBJS) $(DEMOOBJS)
	
$(OBJDIR)/$(SRCDIR): 
	mkdir -p $(OBJDIR)/$(SRCDIR)
	
$(OBJDIR)/$(DEMODIR):
	mkdir -p $(OBJDIR)/$(DEMODIR)		
	
.PHONY: clean
	
clean:
	rm -rf $(OBJDIR)
		

