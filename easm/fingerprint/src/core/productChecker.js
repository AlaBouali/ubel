// domain_scanner.py imports `Product_checker` from a `scanners.components.utils`
// module that wasn't included in the export. Its one call site
// (`Product_checker.product_exists_in_list`) is identical in shape to
// CPE_Parser.product_exists_in_list, so it's reconstructed here from usage.

export class ProductChecker {
  static productExistsInList(productDict, productsList) {
    for (const product of productsList) {
      const sameCore =
        productDict.vendor === product.vendor &&
        productDict.product === product.product &&
        productDict.version === product.version;
      if (!sameCore) continue;
      if ("source" in productDict) {
        if (productDict.source === product.source) return true;
      } else {
        return true;
      }
    }
    return false;
  }
}
