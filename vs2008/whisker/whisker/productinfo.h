#ifndef __PRODUCT_INFO_H__
#define __PRODUCT_INFO_H__

#include <string>
using namespace std;

typedef enum WHISKER_PRODUCT_TYPE {
	PRODUCT_TYPE_UNKNOWN = 0,
	PRODUCT_TYPE_AV,
	PRODUCT_TYPE_AS,
	PRODUCT_TYPE_FW
}WHISKER_PRODUCT_TYPE;

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

	// Non-WMI information

	// This will equal exactly one product type.
	// If a product is detected via WSC in multiple
	// categories, there will be a productInfo
	// structure for each category each with a different
	// productType.
	// This is necessary, in part, because vendors
	// all seem to use the productState fields differently
	// and incorrectly.
	enum WHISKER_PRODUCT_TYPE productType;

	// Use to age out uninstalled products
	bool productStillInstalled;
}productInfo;

#endif // __PRODUCT_INFO_H__