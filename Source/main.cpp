#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <iomanip>
#include <algorithm>
#include <getopt.h>
#include <sstream>
#include <SSLLayer.h>
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"

#include "StatsCollector.h"

#include <glog/logging.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

TEST(TestingDevice, CheckDeviceEth0NotNull) {
    ASSERT_FALSE(pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("eth0") == NULL);
}


// вынесен из EXIT_WITH_ERROR с первой строки
//printUsage(); \

#define EXIT_WITH_ERROR(reason) do { \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)


#define DEFAULT_CALC_RATES_PERIOD_SEC 5

void print_stat_line(std::string description, double counter, std::string measurement, bool log) {
	std::cout 
		<< std::left << std::setw(46) << (std::string(description) + ":") 
		<< std::right << std::setw(15) << std::fixed << std::showpoint << std::setprecision(3) << counter
		<< " [" << measurement << "]" << std::endl; 
	if (log)
		LOG(INFO) << description << ":" << counter << " [" << measurement << "]";
}

void print_traffic_information(std::string host, int inputPakets, int inputTraffic, int outputPakets, int outputTraffic, std::string measurement, bool log){
	std::cout 
		<< std::left << std::setw(42) << host + ": "
		<< "Packets: " << inputPakets + outputPakets << " ("
		<< inputPakets << " IN / " << outputPakets << " OUT); "
		<< "Traffic: " << inputTraffic + outputTraffic<< " [bytes] ("
		<< inputTraffic << " IN / " << outputTraffic << " OUT)" << std::endl; 

	if (log)
		LOG(INFO) << host + ": "
			<< inputPakets + outputPakets << " Packets ("
			<< inputPakets << " IN / " << outputPakets << " OUT) "
			<< inputTraffic + outputTraffic<< " Traffic" << " ("
			<< inputTraffic << " IN / " << outputTraffic << " OUT)";
	}


void printStatsHeadline(const std::string &description)
{
	std::string underline;
	for (size_t i = 0; i < description.length(); i++)
	{
		underline += "-";
	}

	std::cout << std::endl << description << std::endl << underline << std::endl << std::endl;
	LOG(INFO) << description;
}


/**
 * packet capture callback - called whenever a packet arrives
 */
void PacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	pcpp::Packet parsedPacket(packet);

	StatsCollector* traficStatsCollector  = (StatsCollector*)cookie;

	// give the packet to the SSL collector
	traficStatsCollector->collectStats(&parsedPacket, dev->getIPv4Address().toString());
}


/**
 * Print a summary of all statistics collected by the SSLStatsCollector. Should be called when traffic capture was finished
 */
void printStatsSummary(StatsCollector& collector)
{
	printStatsHeadline("General stats");
	print_stat_line("Sample time", collector.getGeneralStats().sampleTime, "Seconds", true);
	print_stat_line("Number of packets", collector.getGeneralStats().numOfPackets, "Packets", true);
	print_stat_line("Rate of packets", collector.getGeneralStats().numOfPackets / collector.getGeneralStats().sampleTime, "Packets/sec", true);
	print_stat_line("Total data", collector.getGeneralStats().amountOfTraffic, "Bytes", true);
	print_stat_line("Rate of data", collector.getGeneralStats().amountOfTraffic / collector.getGeneralStats().sampleTime, "Bytes/sec", true);

	HostsStats hostsStatsToPrint = collector.getClientHelloStats();
	printStatsHeadline("Summary traffic:");
	for(auto& item : hostsStatsToPrint.serverName) 
		print_traffic_information(item.second, 
			hostsStatsToPrint.serverPaketsInput[item.first],
			hostsStatsToPrint.serverTrafficInput[item.first], 
			hostsStatsToPrint.serverPaketsOutput[item.first],
			hostsStatsToPrint.serverTrafficOutput[item.first], "bytes", true);

}


/**
 * Print the current rates. Should be called periodically during traffic capture
 */
void printCurrentRates(StatsCollector& collector)
{
	HostsStats hostsStatsToPrint = collector.getClientHelloStats();

	printStatsHeadline("Current traffic:");
	for(auto& item : hostsStatsToPrint.serverName) 
		if (hostsStatsToPrint.serverTrafficInputPeriod[item.first] > 0 ||
		hostsStatsToPrint.serverTrafficOutputPeriod[item.first] > 0)
			print_traffic_information(item.second, 
				hostsStatsToPrint.serverPaketsInputPeriod[item.first],
				hostsStatsToPrint.serverTrafficInputPeriod[item.first], 
				hostsStatsToPrint.serverPaketsOutputPeriod[item.first],
				hostsStatsToPrint.serverTrafficOutputPeriod[item.first], "bytes", true);
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * activate SSL analysis from live traffic
 */
void analyzeLiveTraffic(pcpp::PcapLiveDevice* dev, bool printRatesPeriodically, int printRatePeriod)
{
	// open the device
	if (!dev->open()) {
		LOG(ERROR) << "Could not open the device";
		EXIT_WITH_ERROR("Could not open the device");
	}

	// start capturing packets and collecting stats
	StatsCollector trafficStatsCollector;
	dev->startCapture(PacketArrive, &trafficStatsCollector);


	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
	{
		pcpp::multiPlatformSleep(printRatePeriod);

		// calculate rates
		if (printRatesPeriodically)
		{
			trafficStatsCollector.calcRates();
			printCurrentRates(trafficStatsCollector);
		}
	}

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// calculate final rates
	trafficStatsCollector.calcRates();

	// print stats summary
	std::cout << std::endl << std::endl
		<< "STATS SUMMARY SSL" << std::endl
		<< "=============" << std::endl;
	LOG(INFO) << "STATS SUMMARY SSL";
	printStatsSummary(trafficStatsCollector);
}


#define MIN(a,b) (((a)<(b))?(a):(b))

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	// Run all tests
	testing::InitGoogleTest(&argc, argv);
	int res = RUN_ALL_TESTS();
	if (res == 1)
		return 1;

	// Getting path, where programm is running
	char path[256];
	size_t len = sizeof(path); 
	int bytes = MIN(readlink("/proc/self/exe", path, len), len - 1);
	path[bytes] = '\0';
	// set level of logging and log path
	FLAGS_logtostderr = false;
	google::SetLogDestination(google::INFO, path);
	// Initialize Google’s logging library.
    google::InitGoogleLogging(argv[0]);

	std::cout << "Log path:" << std::string(path) << std::endl;
	LOG(INFO) << "Log path:" << std::string(path);

	bool printRatesPeriodically = true;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;

    // extract pcap live device by interface name
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("eth0");
	if (dev == NULL)
	{
		std::cerr << "Cannot find interface" << std::endl;
		LOG(ERROR) << "Cannot find interface";
		return 1;
	}

	std::cout
		<< "Interface info:" << std::endl
		<< "   Interface name:        " << dev->getName() << std::endl // get interface name
		<< "   Interface description: " << dev->getDesc() << std::endl // get interface description
		<< "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
		<< "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
		<< "   IPv4:                  " << dev->getIPv4Address().toString() << std::endl 
		<< "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU

	LOG(INFO) << "Interface info:";
	LOG(INFO) << "   Interface name:        " << dev->getName();
	LOG(INFO) << "   Interface description: " << dev->getDesc();
	LOG(INFO) << "   MAC address:           " << dev->getMacAddress();
	LOG(INFO) << "   Default gateway:       " << dev->getDefaultGateway();
	LOG(INFO) << "   IPv4:                  " << dev->getIPv4Address().toString();
	LOG(INFO) << "   Interface MTU:         " << dev->getMtu();

    // start capturing and analyzing traffic
    analyzeLiveTraffic(dev, printRatesPeriodically, printRatePeriod);
}