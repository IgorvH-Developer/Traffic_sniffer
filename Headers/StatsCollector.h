#pragma once

#include <map>
#include <sstream>
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SSLLayer.h"
#include "SystemUtils.h"

#include "HttpLayer.h"
#include <glog/logging.h>

/**
 * An auxiliary struct for encapsulating rate stats
 */
// struct Rate
// {
// 	double currentRate; // periodic rate
// 	double totalRate;	 // overlal rate

// 	void clear()
// 	{
// 		currentRate = 0;
// 		totalRate = 0;
// 	}
// };


/**
 * A struct for collecting general stats
 */
struct GeneralStats
{
	int numOfPackets; // total number of packets
	int packetPeriod; // rate of packets
	int amountOfTraffic; // total traffic in bytes
	int trafficPeriod; // rate of traffic
	double sampleTime; // total stats collection time

	void clear()
	{
		numOfPackets = 0;
		packetPeriod = 0;
		amountOfTraffic = 0;
		trafficPeriod = 0;
		sampleTime = 0;
	}
};


/**
 * A base struct for collecting stats about hosts
 */
struct HostsStats
{
	std::map<std::string, int> serverTrafficInput; // a map for counting the server's traffic  (ip, traffic)
	std::map<std::string, int> serverTrafficInputPeriod; // (ip, trafficRate)
	std::map<std::string, int> serverTrafficOutput; // a map for counting the server's traffic  (ip, traffic)
	std::map<std::string, int> serverTrafficOutputPeriod; // (ip, trafficRate)
	std::map<std::string, int> serverPaketsInput; //  (ip, packetsCount)
	std::map<std::string, int> serverPaketsInputPeriod; // (ip, packetsCountRate)
	std::map<std::string, int> serverPaketsOutput; //  (ip, packetsCount)
	std::map<std::string, int> serverPaketsOutputPeriod; // (ip, packetsCountRate)
	std::map<std::string, std::string> serverName; // a map for matching ip and host name  (ip, hostName)

	virtual ~HostsStats() {}

	virtual void clear()
	{
		serverTrafficInput.clear();
		serverTrafficInputPeriod.clear();
		serverTrafficOutput.clear();
		serverTrafficOutputPeriod.clear();
		serverPaketsInput.clear();
		serverPaketsInputPeriod.clear();
		serverPaketsOutput.clear();
		serverPaketsOutputPeriod.clear();
		serverName.clear();
	}
};



/**
 * The stats collector. Should be called for every packet arriving and also periodically to calculate rates
 */
class StatsCollector
{
public:

	/**
	 * C'tor - clear all structures
	 */
	StatsCollector()
	{
		clear();
	}

	/**
	 * Collect stats for a single packet
	 */
	void collectStats(pcpp::Packet* packet, std::string devIP)
	{
		if (!packet->isPacketOfType(pcpp::IPv4)) {
			return;
		}

		// get IP layer
		pcpp::IPv4Layer* ipLayer = packet->getLayerOfType<pcpp::IPv4Layer>();
		std::string destIP = ipLayer->getDstIPAddress().toString();
		std::string srcIP = ipLayer->getSrcIPAddress().toString();

		// verify packet is TCP and SSL/TLS
		if (!packet->isPacketOfType(pcpp::TCP) || !packet->isPacketOfType(pcpp::SSL))
			if (packet->isPacketOfType(pcpp::TCP))
				collectHTTPStats(packet, devIP, destIP, srcIP);
			else {
				return;
			}

		// collect general SSL traffic stats on this packet
		collectGeneralTrafficStats(packet, devIP, destIP, srcIP);

		// if packet contains one or more SSL messages, collect stats on them
		if (packet->isPacketOfType(pcpp::SSL))
			collectSSLStats(packet, destIP);
		
		// calculate current sample time which is the time-span from start time until current time
		m_GeneralStats.sampleTime = getCurTime() - m_StartTime;
	}

	/**
	 * Calculate rates. Should be called periodically
	 */
	void calcRates()
	{
		// getting current machine time
		double curTime = getCurTime();

		// getting time from last rate calculation until now
		double diffSec = curTime - m_LastCalcRateTime;

		// calculating current rates which are the changes from last rate calculation until now divided by the time passed from
		// last rate calculation until now
		if (diffSec != 0)
		{
			m_GeneralStats.trafficPeriod = (m_GeneralStats.amountOfTraffic - m_PrevGeneralStats.amountOfTraffic) / diffSec;
			m_GeneralStats.packetPeriod = (m_GeneralStats.numOfPackets - m_PrevGeneralStats.numOfPackets) / diffSec;

			for(auto& item : m_HostsStats.serverTrafficInput) {
				std::string hostName = item.first;
				m_HostsStats.serverTrafficInputPeriod[hostName] = 
					m_HostsStats.serverTrafficInput[hostName] - m_PrevHostsStats.serverTrafficInput[hostName];
				m_HostsStats.serverPaketsInputPeriod[hostName] = 
					m_HostsStats.serverPaketsInput[hostName] - m_PrevHostsStats.serverPaketsInput[hostName];
			}
			for(auto& item : m_HostsStats.serverTrafficOutput) {
				std::string hostName = item.first;
				m_HostsStats.serverTrafficOutputPeriod[hostName] = 
					m_HostsStats.serverTrafficOutput[hostName] - m_PrevHostsStats.serverTrafficOutput[hostName];
				m_HostsStats.serverPaketsOutputPeriod[hostName] = 
					m_HostsStats.serverPaketsOutput[hostName] - m_PrevHostsStats.serverPaketsOutput[hostName];
			}

		}

		// saving current numbers for using them in the next rate calculation
		m_PrevGeneralStats = m_GeneralStats;
		m_PrevHostsStats = m_HostsStats;

		// saving the current time for using in the next rate calculation
		m_LastCalcRateTime = curTime;
	}

	/**
	 * Clear all stats collected so far
	 */
	void clear()
	{
		m_GeneralStats.clear();
		m_PrevGeneralStats.clear();
		m_HostsStats.clear();
		m_PrevHostsStats.clear();
		m_LastCalcRateTime = getCurTime();
		m_StartTime = m_LastCalcRateTime;
	}

	/**
	 * Get general stats
	 */
	GeneralStats& getGeneralStats() { return m_GeneralStats; }

	/**
	 * Get client-hello stats
	 */
	HostsStats& getClientHelloStats() { return m_HostsStats; }

private:

	/**
	 * Auxiliary data collected for each flow for help calculating stats on this flow
	 */
	struct SSLFlowData
	{
		bool seenAppDataPacket; // was SSL application data seen in this flow
		bool seenAlertPacket; // was SSL alert packet seen in this flow

		void clear()
		{
			seenAppDataPacket = false;
			seenAlertPacket = false;
		}
	};


	/**
	 * Collect stats relevant for every SSL packet (any SSL message)
	 * This method calculates and returns the flow key for this packet
	 */
	void collectGeneralTrafficStats(pcpp::Packet* packet, std::string devIP, std::string destIP, std::string srcIP)
	{
		pcpp::TcpLayer* tcpLayer = packet->getLayerOfType<pcpp::TcpLayer>();
		if (tcpLayer == NULL) {
			LOG(WARNING) << "Packet is TCP type, but return NULL on getTcpLayer";
			return;
		}

		uint16_t http_port = 80;
		uint16_t https_port = 443;
		if (!(tcpLayer->getDstPort() == http_port || tcpLayer->getSrcPort() == http_port) &&
		!(tcpLayer->getDstPort() == https_port || tcpLayer->getSrcPort() == https_port))
			return;
		
		// count traffic
		int trafficInPaket = tcpLayer->getLayerPayloadSize();
		m_GeneralStats.amountOfTraffic += trafficInPaket;

		// count packet num
		m_GeneralStats.numOfPackets++;

		// counting output packets and their size
		if (devIP == srcIP) {
			m_HostsStats.serverTrafficOutput[destIP] += trafficInPaket;
			m_HostsStats.serverPaketsOutput[destIP] += 1;
		}
		// counting input packets and their size
		if (devIP == destIP) {
			m_HostsStats.serverTrafficInput[srcIP] += trafficInPaket;
			m_HostsStats.serverPaketsInput[srcIP] += 1;
		}
	}

	/**
	 * Collect stats relevant for several kinds SSL messages
	 */
	void collectSSLStats(pcpp::Packet* sslPacket, std::string destIP)
	{
		// go over all SSL messages in this packet
		pcpp::SSLLayer* sslLayer = sslPacket->getLayerOfType<pcpp::SSLLayer>();
		if (sslLayer == NULL) {
			LOG(WARNING) << "Packet is SSL type, but return NULL on getSslLayer";
			return;
		}

		while (sslLayer != NULL)
		{
			pcpp::SSLRecordType recType = sslLayer->getRecordType();

			// check if the layer is an handshake message
			if (recType == pcpp::SSL_HANDSHAKE)
			{
				 pcpp::SSLHandshakeLayer* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslLayer);
				if (handshakeLayer == NULL)
					continue;

				// try to find client-hello message
				pcpp::SSLClientHelloMessage* clientHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();

				// collect client-hello stats
				if (clientHelloMessage != NULL)
				{
					std::string hostName = "";
					pcpp::SSLServerNameIndicationExtension* sniExt = clientHelloMessage->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
					if (sniExt != NULL)
						hostName = sniExt->getHostName();

					if (!hostName.empty()) 
						m_HostsStats.serverName[destIP] = hostName;
				}
			}
			sslLayer = sslPacket->getNextLayerOfType<pcpp::SSLLayer>(sslLayer);
		}
	}



	void collectHTTPStats(pcpp::Packet* packet, std::string devIP, std::string destIP, std::string srcIP)
	{
		collectGeneralTrafficStats(packet, devIP, destIP, srcIP);

		// add host name
		if (packet->isPacketOfType(pcpp::HTTPRequest)) {
			pcpp::HttpRequestLayer* req = packet->getLayerOfType<pcpp::HttpRequestLayer>();
			pcpp::HeaderField* hostField = req->getFieldByName(PCPP_HTTP_HOST_FIELD);
				if (hostField != NULL)
					m_HostsStats.serverName[destIP] = hostField->getFieldValue();
		}
	}

	double getCurTime(void)
	{
	    struct timeval tv;

	    gettimeofday(&tv, NULL);

	    return (((double) tv.tv_sec) + (double) (tv.tv_usec / 1000000.0));
	}

	GeneralStats m_GeneralStats;
	GeneralStats m_PrevGeneralStats;
	HostsStats m_HostsStats;
	HostsStats m_PrevHostsStats;

	std::map<uint32_t, SSLFlowData> m_FlowTable;

	double m_LastCalcRateTime;
	double m_StartTime;
};