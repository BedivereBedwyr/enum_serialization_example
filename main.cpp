#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <fstream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

enum AuthProtocol {
    SHA1,
    MD5
};

struct Entry {
    std::string name;
    u_int interval;

    static Entry deserialize(const boost::property_tree::ptree& pt)
    {
        Entry entry;
        entry.name = pt.get<std::string>("name");
        entry.interval = pt.get<u_int>("interval");
        return entry;
    }
};

struct Agent {
    std::string mib;
    std::string snmp_name;
    AuthProtocol authProtocol;

    static Agent deserialize(const boost::property_tree::ptree& pt)
    {
        Agent agent;
        agent.mib = pt.get<std::string>("mib");
        agent.snmp_name = pt.get<std::string>("snmp_name");
        agent.authProtocol = pt.get<AuthProtocol>("authProtocol");
        return agent;
    }
};

class AuthProtocolTranslator
{
public:
    typedef std::string external_type;
    typedef AuthProtocol internal_type;

    boost::optional<internal_type> get_value(const external_type& v) {
        if (v == "MD5")
            return AuthProtocol::MD5;
        else if (v == "SHA1")
            return AuthProtocol::SHA1;
        return boost::none;
    }

    boost::optional<external_type> put_value(const internal_type& v) {
        if (v == AuthProtocol::MD5)
            return external_type{"MD5"};
        else if (v == AuthProtocol::SHA1)
            return external_type{"SHA1"};
        return boost::none;
    }
};

namespace boost { namespace property_tree {
template<>
struct translator_between<std::string, AuthProtocol>
{
    typedef AuthProtocolTranslator type;
};

}}

std::pair<Agent, std::vector<Entry>> session;

void readConfig()
{
    std::ifstream jsonFile("teste.json");
    if (!jsonFile) {
        std::cerr << "failed to open" <<std::endl;
        return;
    }
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(jsonFile, pt);

    Agent agent;
    agent.mib = pt.get<std::string>("agent.mib");
    agent.snmp_name = pt.get<std::string>("agent.snmp-name");
    agent.authProtocol = pt.get<AuthProtocol>("agent.authentication-protocol");
    std::vector<Entry> entries;
    for (const auto& entry : pt.get_child("agent.entries")) {
        auto ret = Entry::deserialize(entry.second);
        entries.push_back(ret);
    }
    session = {agent, entries};
}

void printConfig(const std::pair<Agent, std::vector<Entry>>& data)
{
    std::stringstream ss;
    ss << "mib: " << data.first.mib << "\nsnmp_name: " << data.first.snmp_name << "\nauthProtocol: " <<
          data.first.authProtocol;
    std::cout << ss.str() << std::endl;
}

int main()
{
    readConfig();
    printConfig(session);
    return 0;
}
