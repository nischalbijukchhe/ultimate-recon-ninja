go mod tidy
install all required modules

Add go-sqlite3 dependency:

bashgo get github.com/mattn/go-sqlite3

Build the binary:

bashgo build -o usr cmd/usr/main.go

Run your first scan:

bash./usr scan example.com --mode passive --format html --output report.html

With AI enhancement (requires Ollama):

bash# Start Ollama first
ollama pull mistral

# Run scan with AI
./usr scan example.com --mode aggressive --ai
This framework is superior to Amass, Subfinder, and Assetfinder because it combines:

Multiple passive sources
Active DNS brute forcing
AI-enhanced pattern discovery
JavaScript parsing
Cloud asset detection
Historical tracking
Change detection
Plugin extensibility

All with zero paid APIs required!
