import styled from 'styled-components';
import { ChangeEvent, RefObject } from 'react';
import { GENDER } from 'utils';

interface RegistInfoInputProps {
  title: string;
  holderText: string;
  inputRef: RefObject<HTMLInputElement>;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
}

interface RegistInfoSelectBoxProps {
  title: string;
  value: string;
  onChange: (e: ChangeEvent<HTMLSelectElement>) => void;
}

const RegistInfoInput = ({
  title,
  holderText,
  inputRef,
  onChange,
}: RegistInfoInputProps) => {
  return (
    <S.InputBox>
      <S.Title>{title}</S.Title>
      <Input placeholder={holderText} ref={inputRef} onChange={onChange} />
    </S.InputBox>
  );
};

const RegistInfoSelectBox = ({
  title,
  value,
  onChange,
}: RegistInfoSelectBoxProps) => {
  return (
    <S.InputBox>
      <S.Title>{title}</S.Title>
      <S.SelectBox value={value} onChange={onChange}>
        <option value={GENDER.MALE}>남성</option>
        <option value={GENDER.FEMALE}>여성</option>
      </S.SelectBox>
    </S.InputBox>
  );
};

const S = {
  InputBox: styled.div`
    width: 100%;
    padding: 0 18px 30px;
  `,
  Title: styled.div`
    font-weight: ${({ theme }) => theme.font.weight.body2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    margin-bottom: 12px;
  `,
  SelectBox: styled.select`
    width: 100%;
    height: 56px;
    border: none;
    background-color: ${({ theme }) => theme.color.gray4};
    padding: 0 16px;
    border-radius: 8px;
    font-weight: ${({ theme }) => theme.font.weight.body3};
    font-size: ${({ theme }) => theme.font.size.body3};
    font-family: ${({ theme }) => theme.font.family.body3};
    &:focus {
      outline: none;
    }
  `,
};

const Input = styled.input`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 56px;
  padding: 12px 16px;
  align-items: center;
  gap: 4px;
  align-self: stretch;
  border: none;
  background-color: ${({ theme }) => theme.color.background};

  &::placeholder {
    font-size: 14px;
    font-weight: 500;
    line-height: 130%;
    letter-spacing: -0.014px;
    color: ${({ theme }) => theme.color.gray3};
  }
  &:focus {
    outline: none;
    border-bottom: 1px solid ${({ theme }) => theme.color.main};
  }
`;

export { RegistInfoInput, RegistInfoSelectBox };
