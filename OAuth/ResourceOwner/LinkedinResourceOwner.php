<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * LinkedinResourceOwner.
 *
 * @author Francisco Facioni <fran6co@gmail.com>
 * @author Joseph Bielawski <stloyd@gmail.com>
 */
class LinkedinResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = [
        'identifier' => 'id',
        'nickname' => 'emailAddress',
        'firstname' => 'firstName.localized.en_US',
        'lastname' => 'lastName.localized.en_US',
        'email' => 'emailAddress',
        'profilepicture' => 'profilePicture.displayImage~.elements.1.identifiers.0.identifier',
    ];

    /**
     * {@inheritdoc}
     */
    protected function doGetTokenRequest($url, array $parameters = array())
    {
        return $this->httpRequest($this->normalizeUrl($url, $parameters), null, array(), 'POST');
    }

    /**
     * {@inheritdoc}
     */
    protected function doGetUserInformationRequest($url, array $parameters = array())
    {
        return parent::doGetUserInformationRequest(str_replace('access_token', 'oauth2_access_token', $url), $parameters);


    }

    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        $response = parent::getUserInformation($accessToken, $extraParameters);
        $responseData = $response->getData();
        // The user info returned by /me doesn't contain the email so we make an extra request to fetch it
        $content = $this->httpRequest(
            $this->normalizeUrl($this->options['email_url'], $extraParameters),
            null,
            ['Authorization' => 'Bearer '.$accessToken['access_token']]
        );
        $emailResponse = $this->getResponseContent($content);
        if (isset($emailResponse['elements']) && \count($emailResponse['elements']) > 0) {
            $responseData['emailAddress'] = $emailResponse['elements'][0]['handle~']['emailAddress'];
        }
        // errors not handled because I don't see any relevant thing to do with them
        $response->setData($responseData);


        return $response;
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(array(
            'authorization_url' => 'https://www.linkedin.com/oauth/v2/authorization',
            'access_token_url' => 'https://www.linkedin.com/oauth/v2/accessToken',
            'infos_url' => 'https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))',
            'email_url' => 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',

            'csrf' => true,

            'use_bearer_authorization' => false,
        ));
    }
}
