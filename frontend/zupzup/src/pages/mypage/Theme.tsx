import { useState } from 'react';
import { TopNavigation } from 'components';
import { URL } from 'utils';
import styled from 'styled-components';

import CheckSvg from 'assets/icons/check.svg?react';

const Theme = () => {
  const [selectedList, setSelectedList] = useState<number>(0);

  const handleListClick = (index: number) => {
    setSelectedList(index);
  };

  const listData = ['밝은 모드', '어두운 모드', '시스템 설정과 같이'];
  return (
    <S.Wrap>
      <TopNavigation
        title="테마 설정"
        rightComponent={<></>}
        navigationTo={URL.SETTING.HOME}
      />
      <S.List>
        {listData.map((item, index) => (
          <S.EachList key={index} onClick={() => handleListClick(index)}>
            {item}
            {selectedList === index && <CheckSvg />}
          </S.EachList>
        ))}
      </S.List>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    overflow: hidden;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
    color: ${({ theme }) => theme.color.dark};
  `,
  List: styled.div`
    margin: 20px;
    font-size: ${({ theme }) => theme.font.size.focus1};
    font-family: ${({ theme }) => theme.font.family.focus1};
  `,
  EachList: styled.div`
    cursor: pointer;
    font-size: ${({ theme }) => theme.font.size.focus1};
    font-family: ${({ theme }) => theme.font.family.body2};
    height: fit-content;
    min-height: 52px;
    padding: 10px 0;
    display: flex;
    width: 100%;
    justify-content: space-between;
    align-items: flex-end;

    & svg {
      filter: invert(52%) sepia(89%) saturate(1764%) hue-rotate(138deg)
        brightness(99%) contrast(101%);
    }
  `,
};

export default Theme;
