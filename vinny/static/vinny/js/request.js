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

function initTooltipster(element, umProfileStore, displayUserCard) {
    $(element).tooltipster({
        animation: 'fade',
	delay: 200,
        theme: 'tooltipster-default',
        trigger: 'hover',
        position: 'top',
        iconCloning: false,
        maxWidth: 400,
	contentAsHTML: true,
        interactive: true,
        content: 'Loading...',
        functionReady: function (instance, helper) {
            var self = $(helper.origin);
            var userUrl = self.attr('href')+"?quick=1";
            if(umProfileStore.hasOwnProperty(userUrl)){
                displayUserCard(instance, umProfileStore[userUrl]);
                // load from cache                                                                                                                                         
            }
            else {
                $.get(userUrl, function(data) {
                    umProfileStore[userUrl] = data;
                    return displayUserCard(instance, data);

                });
            }
        }
    });
}


$(document).ready(function() {

    $('.tooltippy').tooltipster({
	maxWidth:200});
    
    var $modal = $('#modal');
    var $largemodal = $('#largemodal');
    $(document).on("click", "#reqaccess", function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
		$modal.html(resp).foundation('open');
            }
        });

    });

    $(document).on("click", ".orig_report", function(event) {
	event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
                $largemodal.html(resp).foundation('open');
            }
        });
    });

    $(document).on("click", "#downloadics", function(event) {
        var cal = ics($("#uid").text());
        var publishdate = $("#publishdate").text();
        var title = $("#case_title").text();
        cal.addEvent(title + " public (tentative)", title, "Pittsburgh, PA", publishdate, publishdate);
        cal.download();
    });

    var umProfileStore = {};
    
    var displayUserCard = function(instance, data) {
	instance.content(data);
    }
    
    initTooltipster(".vendor-participant", umProfileStore, displayUserCard);

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
    
});
