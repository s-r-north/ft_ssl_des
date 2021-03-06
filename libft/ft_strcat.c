/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcat.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/27 18:31:32 by snorth            #+#    #+#             */
/*   Updated: 2017/03/08 15:48:27 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strcat(char *s1, const char *s2)
{
	size_t i;
	size_t j;

	i = -1;
	while (s1[++i] != 0)
		;
	j = -1;
	while (s2[++j] != 0)
		s1[i++] = s2[j];
	s1[i] = 0;
	return (s1);
}
