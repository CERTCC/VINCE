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


    $('#moreVendor').click(function(e) {
        $("#hidevendors").toggle();
        $("#moreVendors").toggle();
        $("#lessVendors").toggle();
        e.preventDefault();
    });

     $('#lessVendor').click(function(e) {
        $("#hidevendors").toggle();
        $("#moreVendors").toggle();
        $("#lessVendors").toggle();
        e.preventDefault();

     });


    if (document.getElementById('tickets')) {
        var tickets = JSON.parse(document.getElementById('tickets').textContent);
    }

    var cellClickFunction = function(e, cell) {
        var url_mask = "/vince/ticket/" + cell.getRow().getData().id;
        window.location = url_mask;
    };

    if (tickets) {
        var table = new Tabulator("#tkt-table", {
            data:tickets, //set initial table data                                                                                           
            layout:"fitColumns",
            placeholder:"No Tickets",
	    tooltipsHeader:true,
            columns:[
                {title:"Ticket", field:"ticket", cellClick: cellClickFunction},
                {title:"Title", field:"title", cellClick: cellClickFunction},
                {title:"Status", field:"status", cellClick: cellClickFunction},
		{title:"Created", field:"created", cellClick: cellClickFunction},
		{title:"Days Open", field:"open_for", cellClick:cellClickFunction},
                {title:"Last Modified", field:"date", cellClick: cellClickFunction},
		{title:"Days since Modified", field:"stale_for", cellClick:cellClickFunction},
            ],

        });
    }

    $(document).on("change", "#select_user", function(event) {
	var url = '/vince/user/report/?user=' + $(this).val();
	location.href=url;
    });
    
});
