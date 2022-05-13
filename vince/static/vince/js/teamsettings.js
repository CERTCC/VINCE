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
function onBeforeUnload(e) {
    e.preventDefault();
    e.returnValue = '';
    return;
}


$(document).ready(function() {

    window.addEventListener('beforeunload', onBeforeUnload);

    $('form').submit(function () {
	window.removeEventListener('beforeunload', onBeforeUnload);
    });

    var simplemde = new EasyMDE({element: $("#id_vulnote_template")[0],
				   previewRender: function(plainText) {
				       var preview = document.getElementsByClassName("editor-preview-side")[0];
				       preview.innerHTML = this.parent.markdown(plainText);
				       preview.setAttribute('id','editor-preview');
				       return preview.innerHTML;
				   },
				 autoDownloadFontAwesome: false,
				 uploadImage:false,
				 hideIcons: ['image'],
				 showIcons: ['upload-image'],
				 renderingConfig: {
                                     singleLineBreaks: false,
                                 }
				});
    
    
});
