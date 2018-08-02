/*
 * Copyright (C) 2018 Orange Applications for Business
 * 
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution 
 * or at 'https://opensource.org/licenses/BSD-3-Clause'. 
 */

/* Orange PCAP to C buffer converter
 * 
 * Module name: PCAP2C
 * Version:     1.0
 * Created:     2017-07-24 by Frédéric Berger
 */
/*
 * How to read a packet capture file.
 */

/*
 * Step 1 - Add includes
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>

#include <string>
#include <list>
#include <fstream>
#include <sstream>
#include <iostream>
#include <fstream>
#include <iomanip>

void replaceAll(std::string& str, const std::string& from,
		const std::string& to) {
	if (from.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}

int main(int argc, char *argv[]) {
	const char* empty = "";
	char* prefix = (char*) empty;
	char* filename = (char*) empty;
	char* base_filename = (char*) empty;
	char* filelist = (char*) empty;
	unsigned char bheader = 0;
	unsigned char bc_buffer = 0;
	unsigned char barray = 0;
	unsigned char barrayheader = 0;
	unsigned char bverbose = 0;
	unsigned char bAutoPrefix = 0;
	unsigned long max=0;
	int c;

	while ((c = getopt(argc, argv, "Pp:i:l:hcavAf:m:")) != -1) {
		switch (c) {
		case 'p':
			prefix = optarg;
			break;
		case 'P':
			bAutoPrefix = 1;
			break;
		case 'i':
			filename = optarg;
			break;
		case 'l':
			filelist = optarg;
			break;
		case 'h':
			bheader = 1;
			break;
		case 'c':
			bc_buffer = 1;
			break;
		case 'f':
			base_filename = optarg;
			break;
		case 'm':
			max = atol(optarg);
			break;
		case 'v':
			bverbose = 1;
			break;
		case 'a':
			barray = 1;
			break;
		case 'A':
			barrayheader = 1;
			break;
		case '?':
			if (optopt == 'i')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character %x - %c.\n", optopt,
						c);
			return 1;
		default:
			abort();
		}
	}

	/*
	 * Step 2 - Get a file name
	 */

	if ((strcmp(filename, "")) || (strcmp(filelist, ""))) {

		std::list < std::string > filenames;
		// Fill list
		if (strcmp(filelist, "")) {
			std::ifstream infile(filelist);
			std::string tmp;
			while (std::getline(infile, tmp)) {
				filenames.push_back(tmp);
			}
			infile.close();
		}

		if (strcmp(filename, "")) {
			filenames.push_back(std::string(filename));
		}

		std::stringstream ssources;
		std::stringstream sheader;
		std::stringstream sarray;
		std::stringstream sexternal;
		std::stringstream snamearray;
		std::stringstream ssizearray;
		int array_count = 0;

		std::ofstream* ofc=NULL;
		std::ofstream* ofh=NULL;

		std::string base_file(base_filename); 
		if (base_file!="")
		{
			std::string fileC=base_file+".c";
			std::string fileH=base_file+".h";
			ofc=new std::ofstream(fileC.c_str());
			ofh=new std::ofstream(fileH.c_str());
			
			(*ofh) << "// Code generated with pcap2c from OAB" <<std::endl;
			(*ofh) << "#ifndef PCAP_HEADERS" <<std::endl;
			(*ofh) << "#define PCAP_HEADERS" <<std::endl;
			
			(*ofc)<<"// Code generated with pcap2c from OAB"<<std::endl;
			(*ofc)<< "#include \"buffer.h\""<<std::endl;


		}
		unsigned long counter=0;

		for (std::list<std::string>::iterator it = filenames.begin();
				it != filenames.end(); it++) {
			std::string file = *it;

			/*
			 * Step 3 - Create an char array to hold the error.
			 */

			// Note: errbuf in pcap_open functions is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
			//       PCAP_ERRBUF_SIZE is defined as 256.
			// http://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html
			char errbuff[PCAP_ERRBUF_SIZE];

			/*
			 * Step 4 - Open the file and store result in pointer to pcap_t
			 */

			// Use pcap_open_offline
			// http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
			pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

			/*
			 * Step 5 - Create a header and a data object
			 */

			// Create a header object:
			// http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
			struct pcap_pkthdr *header;

			// Create a character array using a u_char
			// u_char is defined here:
			// C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Include\WinSock2.h
			// typedef unsigned char   u_char;
			const u_char *data;

			std::string pref(prefix);

			if (bAutoPrefix) {
				pref = file;

				size_t t = pref.find_last_of("/");
				if (t < pref.size()) {
					pref = pref.substr(t + 1, pref.size());
				}

				replaceAll(pref, ".pcap", "");
				replaceAll(pref, " ", "");
				replaceAll(pref, "-", "_");
				pref = pref + "_";
			}

			/*
			 * Step 6 - Loop through packets and print them to screen
			 */
			u_int packetCount = 0;
			while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
			
				counter++;
			
				// Print using printf. See printf reference:
				// http://www.cplusplus.com/reference/clibrary/cstdio/printf/

				// Show the packet number
				packetCount++;
				if (bverbose) {
					std::cerr << "Packet # " << packetCount << std::endl;
					// Show the size in bytes of the packet
					std::cerr << "Packet size: " << header->len << " bytes"
							<< std::endl;

					// Show a warning if the length captured is different
					if (header->len != header->caplen)
						std::cerr
								<< "Warning! Capture size different than packet size: "
								<< header->len << " bytes" << std::endl;

					// Show Epoch Time
					std::cerr << "Epoch Time: " << header->ts.tv_sec << ":"
							<< header->ts.tv_usec << " seconds" << std::endl;
				}
				if (bheader) {
					//sheader << " extern unsigned char " << std::dec << pref << counter << "pkt"
					sheader << " extern unsigned char " << std::dec << pref << "pkt"
							<< packetCount << "[" << header->len << "];"
							<< std::endl;
				}

				if ( barray || barrayheader || ofc )
				{
					if (array_count != 0)
					{
						sarray << "," << std::endl;
						snamearray << "\"," << std::endl << "\"";
						ssizearray << "," << std::endl;
					}
					sexternal << "extern unsigned char " << std::dec << pref << "pkt" << packetCount << "["<<header->len<<"];\n";
					//sexternal << "extern unsigned char " << std::dec << pref << counter << "pkt" << packetCount << "[];\n";
					//sarray << std::dec << pref << counter << "pkt" << packetCount;
					//snamearray << std::dec << pref << counter << "pkt" << packetCount;
					sarray << std::dec << pref <<  "pkt" << packetCount;
					snamearray << std::dec << pref <<  "pkt" << packetCount;
					ssizearray << header->len;
					array_count++;
				}

				if (bc_buffer)
				{
					//ssources << "unsigned char " << std::dec << pref << counter << "pkt" << std::dec << packetCount
					ssources << "unsigned char " << std::dec << pref <<  "pkt" << std::dec << packetCount
							<< "[" << std::dec << header->len << "]={";

					// loop through the packet and print it as hexidecimal representations of octets
					// We also have a function that does this similarly below: PrintData()
					for (u_int i = 0; (i < header->caplen); i++) {
						// Start printing on the next after every 16 octets
						if ((i % 16) == 0)
							ssources << std::endl;

						// Print each octet as hex (x), make sure there is always two characters (.2).
						ssources << "0x" << std::hex << std::setw(2)
								<< std::setfill('0') << (int) data[i];						
						//ssources << (int)data[i];

						if (i != header->caplen - 1) {
							ssources << ", ";
						}
					}

					// Add two lines between packets
					ssources << "};" << std::endl << std::endl;
				}
				
				if (ofc) {
					//(*ofc) << "unsigned char " << std::dec << pref << counter << "pkt" << std::dec << packetCount
					(*ofc) << "unsigned char " << std::dec << pref <<  "pkt" << std::dec << packetCount
							<< "[" << std::dec << header->len << "]={";

					// loop through the packet and print it as hexidecimal representations of octets
					// We also have a function that does this similarly below: PrintData()
					for (u_int i = 0; (i < header->caplen); i++) {
						// Start printing on the next after every 16 octets
						if ((i % 16) == 0)
							(*ofc) << std::endl;

						// Print each octet as hex (x), make sure there is always two characters (.2).
						(*ofc) << "0x" << std::hex << std::setw(2)
								<< std::setfill('0') << (int) data[i];						
						//ssources << (int)data[i];

						if (i != header->caplen - 1) {
							(*ofc) << ", ";
						}
					}

					// Add two lines between packets
					(*ofc) << "};" << std::endl << std::endl;
					
					if (max!=0)
					{
						if ((counter%max)==0)
						{
							std::cerr<<"Current counter is "<< counter << " looping"<< std::endl;
							// loop on file
							ofc->close();
							delete ofc;
							std::string fileC=base_file+ std::to_string(counter/max)+".c";
							std::cerr<<"Create file "<< fileC.c_str()<<std::endl;
							ofc=new std::ofstream(fileC.c_str());
							
							(*ofc)<<"// Code generated with pcap2c from OAB"<<std::endl;
							(*ofc)<< "#include \"buffer.h\""<< std::endl << std::endl;
						}
					}
				}

			}

		}
		if (bheader) {
			std::cout << sheader.str() << std::endl;			
		}
		if (ofh)
		{
			(*ofh) << sheader.str() << std::endl;
		}

		if (bc_buffer) {
			std::cout << ssources.str() << std::endl;
			if (ofc)
			{
				(*ofc) << ssources.str() << std::endl;
			}
		}

		if (barray) {
			std::cout << "unsigned char* pkts[" << std::dec << array_count << "]={"
					<< sarray.str() << "};" << std::endl;
			std::cout << "int pkt_sizes[" << array_count << "]={"
					<< ssizearray.str() << "};" << std::endl;
			
		}
			
		if (barray) {
			std::cout << "char* pkt_names[" << std::dec << array_count << "]={\""
					<< snamearray.str() << "\"};" << std::endl;
			
		}

		if (barrayheader)
		{
			std::cout << sexternal.str() << std::endl;
			std::cout << "extern unsigned char* pkts[" << std::dec << array_count << "];"
					<< std::endl;
			std::cout << "extern int pkt_sizes[" << std::dec << array_count << "];"
					<< std::endl;
			std::cout << "extern char* pkt_names[" << std::dec << array_count << "];"
					<< std::endl;
		}


		if (ofc)
		{

			std::cerr<<"Generate last buffer" << std::endl;
			// loop on file
			ofc->close();
			delete ofc;
			if (max==0)
			{
				max++;
			}
			std::string fileC=base_file+ std::to_string(counter/max+1)+".c";
			std::cerr<<"Create file "<< fileC.c_str()<<std::endl;
			ofc=new std::ofstream(fileC.c_str());

			(*ofc)<<"// Code generated with pcap2c from OAB"<<std::endl;
			(*ofc)<< "#include \"buffer.h\""<< std::endl << std::endl;

			(*ofc) << "unsigned char* pkts[" << std::dec << array_count << "]={"
					<< sarray.str() << "};" << std::endl;
			(*ofc) << "int pkt_sizes[" << array_count << "]={"
					<< ssizearray.str() << "};" << std::endl;
			(*ofc)<< "char* pkt_names[" << std::dec << array_count << "]={\""
								<< snamearray.str() << "\"};" << std::endl;
			ofc->close();
			delete ofc;
		}

		if (ofh)
		{
			(*ofh) << sexternal.str() << std::endl;
			(*ofh) << "extern unsigned char* pkts[" << std::dec << array_count << "];"
					<< std::endl;
			(*ofh) << "extern int pkt_sizes[" << std::dec << array_count << "];"
					<< std::endl;
			(*ofh) << "extern char* pkt_names[" << std::dec << array_count << "];"
					<< std::endl;

			(*ofh)<<"#endif // PCAP_HEADERS"<<std::endl;
			ofh->close();
			delete ofh;
		}
	} else {
		std::cout
				<< "Usage: [-P|-p prefix] (-i pcap_filename|-l pcap_list) -h -c -a -A -v -f base filename -m maximum_packet_by_file"
				<< std::endl;
		std::cout
				<< "\t -P: Set automatic prefix names according to pcap filename"
				<< std::endl;
		std::cout << "\t -p prefix: prefix set before packet name" << std::endl;
		std::cout << "\t -i pcap_filename: name of the pcap filename to parse"
				<< std::endl;
		std::cout
				<< "\t -l pcap_list: name of a file including pcap filenames to parse"
				<< std::endl;
		std::cout << "\t -h: displays content of header file" << std::endl;
		std::cout << "\t -c: displays C arrays" << std::endl;
		std::cout
				<< "\t -a: Display arrays which contains all C arrays and their sizes"
				<< std::endl;
		std::cout << "\t -Aa: Display C array and sizes declaration"
				<< std::endl;

		std::cout << "\t -v: Displays some details about packet" << std::endl;
		std::cout << "\t -f: supply base filename for file generation" << std::endl;
				std::cout << "\t -m: maximum number of packet by C file" << std::endl;

	}
}
		
