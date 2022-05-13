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


if (Dropzone) {
    Dropzone.autoDiscover = false;
}

function autoTaggle(data, taggle) {
    var container = taggle.getContainer();
    var input = taggle.getInput();
    $(input).autocomplete({
        source: data,
        appendTo:container,
        position: { at: "left bottom", of: container },
        select: function(event, data) {
            event.preventDefault();
            if (event.which === 1) {
                taggle.add(data.item.value);
            }
        }
    });
}


$(document).ready(function() {

    var url = $("#sendmsgform").attr("action");

    var simplemde = new EasyMDE({element: $("#id_content")[0],
                                 renderingConfig: {
                                     singleLineBreaks: false,
                                 },
                                 status: false,
				 autoDownloadFontAwesome: false,
                                });

    function submitFormWithoutFiles() {
	var data = $("#sendmsgform").serializeArray();
        $.ajax({
            url: $("#sendmsgform").attr("action"),
            type: "POST",
            data: data,
            success: function(data) {
                var url_mask = $("#sendmsgform").attr("success");
                window.location = url_mask;
            },
	    error: function(request, text, error) {
		$("#error-list").append("<div class=\"alert callout\">Form Invalid</div>").show();
	    }
	       
        });
    }

    $("#dropzonepreview").dropzone ({
        url: url,
        parallelUploads: 5,
        uploadMultiple: true,
        dictDefaultMessage: "",
        paramName: 'attachment',
        addRemoveLinks: true,
        autoProcessQueue: false,
        init: function() {
            var myDropZone = this;
            document.getElementById('sendmsgform').addEventListener("submit", function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (myDropZone.getQueuedFiles().length > 0) {
                    myDropZone.processQueue();
                } else {
                    var content = simplemde.value();
                    if (content != "") {
			submitFormWithoutFiles();
                    } else {
                        alert("You must provide content or an attachment");
                    }
                }
            });
            this.on("sendingmultiple", function(data, xhr, formData) {
                var form = document.getElementById('sendmsgform');
                for(var i=0; i < form.elements.length; i++){
                    var e = form.elements[i];
                    console.log(e.name+"="+e.value);
                    formData.append(e.name, e.value);
                }
            });
            this.on("successmultiple", function(files, response) {
                var url_mask = $("#sendmsgform").attr("success");
                window.location = url_mask;
            });

        }
    });

    if (document.getElementById("group_taggs")) {
        var tag_url = $("#group_taggs").attr("href");
        var assigned_groups = JSON.parse(document.getElementById('assigned_groups').textContent);
        var assignable = JSON.parse(document.getElementById('assignable').textContent);
        console.log(assignable);
        var tags = [];
        var taggle2 =  new Taggle('group_taggs', {
            tags: assigned_groups,
            duplicateTagClass: 'bounce',
            preserveCase: true,
            allowedTags: assignable,
            placeholder: ["Tag a vendor..."],
	    onTagAdd: function(event, tag) {
                if (event) {
		    event.preventDefault();
		}},
	    onBeforeTagRemove: function(event, tag) {
		if (event) {
		    event.preventDefault();
		}}
	});

	autoTaggle(assignable, taggle2);
	
    }
});
