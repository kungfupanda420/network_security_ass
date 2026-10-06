#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include <netinet/tcp.h>

// Analyzes TCP flags and returns the type of scan as a string
const char* classify_packet(const struct tcphdr *tcph);

#endif