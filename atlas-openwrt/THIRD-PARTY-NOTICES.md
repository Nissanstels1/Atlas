# Public Suffix List

`root/usr/lib/atlas/public_suffix_list.dat` contains the ICANN and PRIVATE rules
from the [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat),
retrieved on 2026-10-24. Comments were omitted and Unicode suffixes converted
to ASCII IDNA. Retrieval details and the original checksum are in its header.

The list is made available under the
[Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/).
The modified data is distributed as source in this repository. Atlas application
code retains its existing MIT license. The list helps suggest a site's domain;
an unknown suffix is kept as the exact observed hostname.
