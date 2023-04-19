import pytest
from mock import patch

from w3af.core.data.parsers.doc.url import URL
from w3af.core.data.dc.headers import Headers
from w3af.plugins.grep.missing_headers import Missing_Headers
from w3af.plugins.tests.plugin_testing_tools import mocked_response


class TestMissingHeaders:
    @pytest.fixture
    def missing_headers_instance(self):
        missing_headers_instance = Missing_Headers()
        yield missing_headers_instance
        del missing_headers_instance

    # # # csp header
    # def test_no_csp_headers(
    #     self, testing_plugin_runner, knowledge_base, missing_headers_instance
    # ):
    #     with patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_frame_options_header_missing",
    #     ) as frame_options_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_permitted_cross_domain_policies_header_missing",
    #     ) as permitted_crossdomain_policy_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_referrer_policy_header_missing",
    #     ) as referrer_policy_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_clear_site_data_header_missing",
    #     ) as clear_sitedata_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_embedder_policy_header_missing",
    #     ) as cross_origin_embedder_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_opener_policy_header_missing",
    #     ) as cross_origin_opener_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_resource_policy_header_missing"
    #     ) as cross_origin_resource_header:
    #         frame_options_header.return_value = False
    #         permitted_crossdomain_policy_header.return_value = False
    #         referrer_policy_header.return_value = False
    #         clear_sitedata_header.return_value = False
    #         cross_origin_embedder_header.return_value = False
    #         cross_origin_opener_header.return_value = False
    #         cross_origin_resource_header.return_value = False

    #         body = ""
    #         url = "http://www.w3af.com/"
    #         extra_options = {
    #             "target": url,
    #             "response": mocked_response(
    #                 url=URL(url),
    #                 text_resp="test",
    #                 code=200,
    #                 set_body=True,
    #             ),
    #         }

    #         with patch(
    #             "w3af.core.data.url.HTTPResponse.HTTPResponse.get_body"
    #         ) as get_body_patch:
    #             get_body_patch.return_value = body
    #             testing_plugin_runner.run_plugin(
    #                 missing_headers_instance,
    #                 extra_options=extra_options,
    #             )

    #         vulns = len(knowledge_base.get("Missing_Headers", "missing_content_security_policy_header"))

    #         assert vulns == 1

    # @patch("w3af.core.data.url.HTTPResponse.HTTPResponse.get_body")
    # @patch("w3af.core.data.url.HTTPResponse.HTTPResponse.get_headers")
    # def test_has_csp_headers_in_head(
    #     self,
    #     get_headers_patch,
    #     get_body_patch,
    #     testing_plugin_runner,
    #     knowledge_base,
    #     missing_headers_instance,
    # ):
    #     with patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_frame_options_header_missing",
    #     ) as frame_options_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_permitted_cross_domain_policies_header_missing",
    #     ) as permitted_crossdomain_policy_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_referrer_policy_header_missing",
    #     ) as referrer_policy_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_clear_site_data_header_missing",
    #     ) as clear_sitedata_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_embedder_policy_header_missing",
    #     ) as cross_origin_embedder_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_opener_policy_header_missing",
    #     ) as cross_origin_opener_header, patch(
    #         "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_resource_policy_header_missing"
    #     ) as cross_origin_resource_header:
    #         frame_options_header.return_value = False
    #         permitted_crossdomain_policy_header.return_value = False
    #         referrer_policy_header.return_value = False
    #         clear_sitedata_header.return_value = False
    #         cross_origin_embedder_header.return_value = False
    #         cross_origin_opener_header.return_value = False
    #         cross_origin_resource_header.return_value = False

    #         body = ""
    #         url = "http://www.w3af.com/"
    #         extra_options = {
    #             "target": url,
    #             "response": mocked_response(
    #                 url=URL(url),
    #                 text_resp="test",
    #                 code=200,
    #                 set_body=True,
    #             ),
    #         }

    #         headers = Headers(
    #             [
    #                 ("content-type", "text/html"),
    #                 (
    #                     "Content-Security-Policy",
    #                     "default-src 'self'; img-srcss https://*; child-src 'none';",
    #                 ),
    #             ]
    #         )

    #         get_body_patch.return_value = body
    #         get_headers_patch.return_value = headers
    #         testing_plugin_runner.run_plugin(
    #             missing_headers_instance,
    #             extra_options=extra_options,
    #         )

    #         vulns = len(knowledge_base.get("Missing_Headers", "missing_content_security_policy_header"))

    #         assert vulns == 0

    @pytest.mark.parametrize(
        "headers, expected_vulns",
        [
            (
                Headers([]),
                1,
            ),
            (
                Headers(
                    [
                        ("content-type", "text/html"),
                        (
                            "Content-Security-Policy",
                            "default-src 'self'; img-srcss https://*; child-src 'none';",
                        ),
                    ]
                ),
                0,
            ),
        ],
    )
    
    def test_missing_csp_headers(
        self,
        testing_plugin_runner,
        knowledge_base,
        missing_headers_instance,
        headers,
        expected_vulns,
    ):
        with patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_frame_options_header_missing",
        ) as frame_options_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_permitted_cross_domain_policies_header_missing",
        ) as permitted_crossdomain_policy_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_referrer_policy_header_missing",
        ) as referrer_policy_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_clear_site_data_header_missing",
        ) as clear_sitedata_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_embedder_policy_header_missing",
        ) as cross_origin_embedder_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_opener_policy_header_missing",
        ) as cross_origin_opener_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_resource_policy_header_missing"
        ) as cross_origin_resource_header:
            frame_options_header.return_value = False
            permitted_crossdomain_policy_header.return_value = False
            referrer_policy_header.return_value = False
            clear_sitedata_header.return_value = False
            cross_origin_embedder_header.return_value = False
            cross_origin_opener_header.return_value = False
            cross_origin_resource_header.return_value = False

            body = ""
            url = "http://www.w3af.com/"
            extra_options = {
                "target": url,
                "response": mocked_response(
                    url=URL(url),
                    text_resp="test",
                    code=200,
                    set_body=True,
                ),
            }

            with patch(
                "w3af.core.data.url.HTTPResponse.HTTPResponse.get_body"
            ) as get_body_patch, patch(
                "w3af.core.data.url.HTTPResponse.HTTPResponse.get_headers"
            ) as get_headers_patch:
                get_body_patch.return_value = body
                get_headers_patch.return_value = headers
                testing_plugin_runner.run_plugin(
                    missing_headers_instance,
                    extra_options=extra_options,
                )

            vulns = len(
                knowledge_base.get(
                    "Missing_Headers", "missing_content_security_policy_header"
                )
            )

            assert vulns == expected_vulns

    def test_has_csp_headers_in_body(
        self, testing_plugin_runner, knowledge_base, missing_headers_instance
    ):
        with patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_frame_options_header_missing",
        ) as frame_options_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_permitted_cross_domain_policies_header_missing",
        ) as permitted_crossdomain_policy_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_referrer_policy_header_missing",
        ) as referrer_policy_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_clear_site_data_header_missing",
        ) as clear_sitedata_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_embedder_policy_header_missing",
        ) as cross_origin_embedder_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_opener_policy_header_missing",
        ) as cross_origin_opener_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_resource_policy_header_missing"
        ) as cross_origin_resource_header:
            frame_options_header.return_value = False
            permitted_crossdomain_policy_header.return_value = False
            referrer_policy_header.return_value = False
            clear_sitedata_header.return_value = False
            cross_origin_embedder_header.return_value = False
            cross_origin_opener_header.return_value = False
            cross_origin_resource_header.return_value = False

            body = """<meta http-equiv="somthing else"
                content="default-src 'self'; img-src https://*; child-src 'none';">
                <meta http-equiv="maywhatisthis"
                content="default-src 'self'; img-srsfsc https://*; child-src 'none';">
                <meta http-equiv="Content-Seculicy"
                content="default-src 'sesfslf'; img-src https://*; child-src 'none';">
                <meta http-equiv="Content-Security-Policy"
                content="default-src 'self'; img-srcss https://*; child-src 'none';">
            """
            url = "http://www.w3af.com/"
            extra_options = {
                "target": url,
                "response": mocked_response(
                    url=URL(url),
                    text_resp="test",
                    code=200,
                    set_body=True,
                ),
            }

            with patch(
                "w3af.core.data.url.HTTPResponse.HTTPResponse.get_body"
            ) as get_body_patch:
                get_body_patch.return_value = body
                testing_plugin_runner.run_plugin(
                    missing_headers_instance,
                    extra_options=extra_options,
                )

            vulns = len(knowledge_base.get("Missing_Headers", "missing_content_security_policy_header"))

            assert vulns == 0

    def test_max_reports_csp_header(
        self, testing_plugin_runner, knowledge_base, missing_headers_instance
    ):
        with patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_frame_options_header_missing",
        ) as frame_options_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_x_permitted_cross_domain_policies_header_missing",
        ) as permitted_crossdomain_policy_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_referrer_policy_header_missing",
        ) as referrer_policy_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_clear_site_data_header_missing",
        ) as clear_sitedata_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_embedder_policy_header_missing",
        ) as cross_origin_embedder_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_opener_policy_header_missing",
        ) as cross_origin_opener_header, patch(
            "w3af.plugins.grep.missing_headers.Missing_Headers.check_cross_origin_resource_policy_header_missing"
        ) as cross_origin_resource_header:
            frame_options_header.return_value = False
            permitted_crossdomain_policy_header.return_value = False
            referrer_policy_header.return_value = False
            clear_sitedata_header.return_value = False
            cross_origin_embedder_header.return_value = False
            cross_origin_opener_header.return_value = False
            cross_origin_resource_header.return_value = False

            body = ""
            url = "http://www.w3af.com/"
            extra_options = {
                "target": url,
                "response": mocked_response(
                    url=URL(url),
                    text_resp="test",
                    code=200,
                    set_body=True,
                ),
            }
            missing_headers_instance._reports["contentsecuritypolicy_header"] = 0

            for attempt in range(1, 15):
                with patch(
                    "w3af.core.data.url.HTTPResponse.HTTPResponse.get_body"
                ) as get_body_patch:
                    get_body_patch.return_value = body
                    testing_plugin_runner.run_plugin(
                        missing_headers_instance,
                        extra_options=extra_options,
                    )

                reports = missing_headers_instance._reports["contentsecuritypolicy_header"]

                if attempt > 10:
                    assert reports == 11
                else:
                    assert reports == attempt
