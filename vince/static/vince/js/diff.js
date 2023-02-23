/*#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
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

function jsonWrapper(url, callback) {
  $.getJSON(url, function(data) {
    if (data == null) {
      ajaxError();
    } else {
	callback(data);
    }
  });
}



function fillModal(vulnote_id, revision_id) {
    
    var frame = $('#previewWindow');
    var modal = $('#previewModal');
    var url = "/vince/vulnote/preview/"+ vulnote_id +"/"+revision_id+"/";
    frame.attr("src", url);
    modal.foundation('open');
    $('#previewModal .viewfullscreen').attr('href', url);
    $('#previewModal .switch-to-revision').attr('href', "/vince/vulnote/change_revision/"+vulnote_id+"/"+revision_id+"/");
}



function get_diff_json(url, put_in_element) {
    jsonWrapper(url, function (data) {
	if (!$(put_in_element).find('.diff-container tbody').length > 0) {
	    $(put_in_element).parentsUntil('.panel-group').find('.progress').show(0 , function() {
		tbody = pydifferviewer.as_tbody({differ_output: data.diff});
		$(put_in_element).find('.diff-container table').append(
		    tbody
		);
		if (data.other_changes) {
		    for (var i=0; i < data.other_changes.length; i++) {
			$(put_in_element).find('dl').append($('<dt>'+data.other_changes[i][0]+'</dt>' +
							      '<dd>'+data.other_changes[i][1]+'</dd>'  ));
		    }
		}
		put_in_element.find('.diff-container').show('fast', function() {});
		$(put_in_element).parentsUntil('.panel-group').find('.progress').detach();
	    });
	} else {
            put_in_element.find('.diff-container').show('fast', function() {});
	}
    });
}



$(document).ready(function() {

    $(document).on("click", '.callout-toggle', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
	var rev = $("#"+$(this).attr("data-toggle"));
	get_diff_json(url, rev);
    });

    $(document).on("click", '.fillmodal', function(event) {
        event.preventDefault();
	var vulnote_id = $(this).attr("vnid");
	var rev_id = $(this).attr("rev");
	fillModal(vulnote_id, rev_id);
    });
});
