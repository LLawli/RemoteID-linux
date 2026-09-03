
			/*<![CDATA[*/
			var params = {};
			var pushCanceled = false;
			window.onload = () => {
				var urlParams = new URLSearchParams(window.location.search);
				urlParams.forEach((value, key) => {
					params[key] = value;
				});
				
				params['state'] = params['state'] || "";
				params['scope'] = 'single_signature';
				params['request_Id'] = null;
				params['redirect_uri'] = 'https://sso.acesso.gov.br/login-oauth2-pkce';

				var accounts = null;
				if (accounts !== null) {
					changeToLegacyFlow(false);
					setAccounts(accounts);
				}
				changeArrows();
			};
			function changeArrows() {
				var selects = document.querySelectorAll('.container .form .input select');
				selects.forEach((select) => {
					select.style.backgroundImage = "url('" + window.location.origin + "/api/image/arrow.svg')";
				});
			}
			function setAccounts(accounts) {
				if (accounts.length > 1) {
					var accountInput = document.getElementById("accounts");
					for(var i = 0; i < accounts.length; i++) {
						var option = document.createElement('option');
						option.value = accounts[i].userId +"|"+ accounts[i].hasCell;
						option.text = accounts[i].email;
						accountInput.add(option);
					}
					document.getElementById("input-accounts").classList.remove("hidden");
				} else {
					selectAccount(accounts[0]);
					document.getElementById("input-email").classList.remove("hidden");
				}
			}
			function changeToLegacyFlow(withoutCpf) {
				document.getElementById("input-cpf").classList.add("hidden");
				document.getElementById("cpfButton").classList.add("hidden");
				document.getElementById("oauthButton").classList.remove("hidden");
				if (withoutCpf) {
					document.getElementById("email").removeAttribute("disabled");
					document.getElementById("input-email").classList.remove("hidden");
					document.getElementById("input-pin").classList.remove("hidden");
					document.getElementById("input-totp").classList.remove("hidden");
				}
			}
			function toogleLoading(show) {
				if (show) {
					document.getElementById("oauthButton").classList.add("hidden");
					document.getElementById("loadingButton").classList.remove("hidden");
				} else {
					document.getElementById("loadingButton").classList.add("hidden");
					document.getElementById("oauthButton").classList.remove("hidden");
				}
			}
			function getParams() {
				return {
					...params,
					pin: document.getElementById("pin").value,
					otp: document.getElementById("totp").value,
					certificate_id: document.getElementById("certificados").value || "",
					email: document.getElementById("email").value || "",
				};
			}
			function showModal() {
				authenticationPush();
				Swal.fire({
					html: `
						<span style="display:block;margin:0px 0px 1.25rem;font-size:2.5em;font-weight:600;">Login com Push</span>
						Aguardando Confirmação do Push
						<span style="display:block;font-size:2em;margin:.5rem 0px;letter-spacing:1rem;">${params['request_Id']}</span>
						Confirme o Push enviado para o seu celular ou clique em Cancelar para fazer login com PIN e e-Token.
					`,
					allowEscapeKey: false,
					allowOutsideClick: false,
					confirmButtonText: 'Cancelar',
				}).then((result) => {
					if (result.isConfirmed) {
						pushCanceled = true;
						apiRequest('/api/v0/oauth/rejectauthenticatepush', 'POST', {request_Id: params['request_Id']}, (data, error) => {
							if (error) {
								console.error('Erro ao rejeitar autenticação push:', error);
							}
						});
					}
				});
			}
			function removeEmptyAccountOption() {
				var select = document.getElementById("accounts");
				var options = select.options;
				for (var i = 0; i < options.length; i++) {
					if (options[i].value === "") {
						select.removeChild(options[i]);
						return;
					}
				}
			}
			function selectAccount(account) {
				params['user_id'] = account.userId;
				document.getElementById("email").value = account.email;
				document.getElementById("input-pin").classList.remove("hidden");
				document.getElementById("input-totp").classList.remove("hidden");
				document.getElementById('accounts-error').classList.add('hidden');
				removeEmptyAccountOption();
				if (account.hasCell == "true") {
					showModal();
				}
			}
			function changeAccount(input) {
				var value = input.options[input.selectedIndex].value;
				if (value != ""){
					var values = value.split("|")
					selectAccount({
						userId: values[0],
						hasCell: values[1],
						email: input.options[input.selectedIndex].text,
					});
				}
			}
			function applyCpfMask(input) {
				var value = input.value.replace(/\D/g, '');
				value = value.replace(/(\d{3})(\d)/, '$1.$2');
				value = value.replace(/(\d{3})(\d)/, '$1.$2');
				value = value.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
				input.value = value;
				if (value.length >= 14) {
					if (isCPFValid(value)) {
						document.getElementById('cpfButton').classList.remove('disabled');
					} else {
						document.getElementById('cpf-error').classList.remove('hidden');
					}
				} else {
					document.getElementById('cpf-error').classList.add('hidden');
					document.getElementById('cpfButton').classList.add('disabled');
				}
			}
			function applyTOTPMask(input) {
				input.value = input.value.replace(/\D/g, '');
			}
			function isCPFValid(cpf) {
				cpf = cpf.replace(/\D/g, '');
				if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) {
					return false;
				}
				var sum = 0;
				for (var i = 0; i < 9; i++) {
					sum += parseInt(cpf.charAt(i)) * (10 - i);
				}
				var firstCheckDigit = 11 - (sum % 11);
				if (firstCheckDigit >= 10) firstCheckDigit = 0;
				if (firstCheckDigit !== parseInt(cpf.charAt(9))) {
					return false;
				}
				sum = 0;
				for (var j = 0; j < 10; j++) {
					sum += parseInt(cpf.charAt(j)) * (11 - j);
				}
				var secondCheckDigit = 11 - (sum % 11);
				if (secondCheckDigit >= 10) secondCheckDigit = 0;
				if (secondCheckDigit !== parseInt(cpf.charAt(10))) {
					return false;
				}
				return true;
			}
			function apiRequest(url, method = 'GET', body = null, callback = () => {}) {
				var XHR = new XMLHttpRequest();
				XHR.open(method, url);
				XHR.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded;charset=UTF-8');
				XHR.onreadystatechange = function () {
					if (XHR.readyState === 4) {
						if (XHR.status >= 200 && XHR.status < 300) {
							callback(XHR.responseText, null);
						} else {
							callback(null, {status: XHR.status, response: XHR.responseText});
						}
					}
				};
				XHR.send(body ? new URLSearchParams(body).toString() : null);
			}
			function verifyNewUser() {
				var params = getParams();
				var cpf = document.getElementById('cpf').value;
				if (isCPFValid(cpf)) {
					cpf = cpf.replace(/\D/g, '');
					apiRequest(`/api/v0/oauth/verify-user?cpf=${cpf}&client_id=${params.client_id}`, 'GET', null, (data, error) => {
						if (data === "certisign") {
							params['cpf'] = cpf;
							var remoteIdUrlV2 = 'https://remote-api.certisign.com.br';
							window.location.replace(`${remoteIdUrlV2}/api/v1/oauth/authorize?${new URLSearchParams(params).toString()}`);
						} else if (data === "remoteid") {
							params['login_hint'] = cpf;
							window.location.replace(`/api/v0/oauth/authorize?${new URLSearchParams(params).toString()}`);
						} else {
							changeToLegacyFlow(true);
						}
					});
				}
			}
			function authenticationPush() {
				pushCanceled = true;
				var params = getParams();
				apiRequest('/api/v0/oauth/authenticatepush', 'POST', params, (data, error) => {
					Swal.close();
					if (data) {
						var response = JSON.parse(data);
						handleResponse(response, true);
					} else if (error && !pushCanceled) {
						Swal.fire(
							'Erro na autenticação',
							'Por favor, utilize o Pin e e-token para se autenticar.',
							'error'
						);
					}
				});
			}
			function handleResponse(response, isPushFlow = false) {
				if (response.oauth_do_login_error != "no_error") {
					Swal.fire({
						icon: 'error',
						title: 'Erro na autenticação',
						text: response.message,
					});
					toogleLoading(false);
				} else {
					document.getElementById("input-pin").classList.add("hidden");
					document.getElementById("input-totp").classList.add("hidden");
					document.getElementById("input-email").classList.add("hidden");
					document.getElementById("input-accounts").classList.add("hidden");

					params['authentication_Id'] = response.authenticationId || "";
					var certificates = response.certificates;

					// usuario não possui certificado
					if (certificates.length == 0) {
						Swal.fire({
							icon: 'error',
							title: 'Nenhum certificado encontrado',
							text: 'Nenhum certificado foi encontrado para o usuário autenticado.',
						});
						toogleLoading(false);
					} else {
						// usuario possui apenas um certificado
						var inputCertificados = document.getElementById("certificados");
						if (certificates.length == 1) {
							var option = document.createElement('option');
							option.value = certificates[0].id;
							option.text = certificates[0].alias;
							inputCertificados.add(option);
							inputCertificados.value = certificates[0].id;
							getCodeAuthorization(isPushFlow);
						} else {
						// usuario possui vários certificados
							document.getElementById("input-certificados").classList.remove("hidden");
							for (var i = 0; i < certificates.length; i++) {
								var option = document.createElement('option');
								option.value = certificates[i].id;
								option.text = certificates[i].alias;
								inputCertificados.add(option);
							}
							document.getElementById("oauthButton").innerHTML = "Selecionar Certificado";
							toogleLoading(false);
						}
					}
				}
			}
			function oauth() {
				toogleLoading(true);
				var params = getParams();
				if (params.email == "") {
					document.getElementById('accounts-error').classList.remove('hidden');
					toogleLoading(false);
					return;
				}
				if (params.certificate_id == "") {
					authentication();
				} else {
					getCodeAuthorization(params.authentication_Id != "");
				}
			}
			function authentication() {
				apiRequest('/api/v0/oauth/authenticate', 'POST', getParams(), (data, error) => {
					if (error) {
						Swal.fire(
							'Erro na autenticação',
							`${JSON.parse(error.response || "{}").message || 'Ocorreu um erro ao autenticar o usuário.'}`,
							'error'
						);
						toogleLoading(false);
					} else {
						var response = JSON.parse(data);
						handleResponse(response);
					}
				});
			}
			function getCodeAuthorization(isPushFlow = false) {
				var url = "/api/v0/oauth/getcodeauthorization" + (isPushFlow ? "push" : "");
				var form = document.createElement("form");
			    form.setAttribute("method", "post");
			    form.setAttribute("action", url);
				form.style.display = "none";
				var params = getParams();
			    for (var key in params) {
			        if (params.hasOwnProperty(key)) {
			            var hiddenField = document.createElement("input");
			            hiddenField.setAttribute("type", "hidden");
			            hiddenField.setAttribute("name", key);
			            hiddenField.setAttribute("value", params[key]);
			            form.appendChild(hiddenField);
					}
			    }
			    document.body.appendChild(form);
			    form.submit();
			}
			/*]]>*/
		