/*#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################
*/
$(document).ready(function() {



    if (document.getElementById('vuls_data')) {
         var data = JSON.parse(document.getElementById('vuls_data').textContent);
         console.log(data);
     }


    var vulCellClick = function(e, cell) {
	var url_mask = cell.getRow().getData().vuldetaillink;
        window.location = url_mask;
    };

    function statusCellClick(cell) {
	var url_mask = cell.getRow().getData().editstatus;
	return {url: url_mask};
    };
    
    if (data) {
	var status = false;
	if (document.getElementById('showstatusbutton')) {
	    status = true;
	}
        var table = new Tabulator("#vuls-table", {
            data:data, //set initial table data
	    placeholder: "No vulnerabilities have been added",
            layout:"fitColumns",
            columns:[
                {title:"Name", field:"cve", cellClick: vulCellClick},
                {title:"Description", field:"description", cellClick: vulCellClick},
		{title:"Exploits", field:"exploits", cellClick: vulCellClick},
                {title:"Date Added", field:"date_added", cellClick: vulCellClick},
		{title:"Status", field:"status", formatterParams:statusCellClick, visible:status, formatter:"link"},
            ],

        });
    }

});
