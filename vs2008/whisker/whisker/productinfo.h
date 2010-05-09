#ifndef __PRODUCT_INFO_H__
#define __PRODUCT_INFO_H__

#include <string>
using namespace std;

// These values are based on data in WMI.
// Specifically older \\root\SecurityCenter entries.
// Only a couple of these entries are relevant
// to \\root\SecurityCenter2 products (Vista SP1 and greater)
// but we might be able to fill the entries in via
// other means, such as installed products 
// for version and company name
// and scraping registry keys manually
typedef struct productInfo {
	wstring companyName;
	wstring displayName;
	wstring instanceGuid;
	bool productEnabled;
	bool productHasNotifiedUser;
	bool productUptoDate;
	bool productWantsWscNotifications;
	wstring versionNumber;
	int productState;
}productInfo;

#endif // __PRODUCT_INFO_H__